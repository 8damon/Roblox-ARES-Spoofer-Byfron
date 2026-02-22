use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::CONTROLTRACE_HANDLE;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2,
    OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    PROPERTY_DATA_DESCRIPTOR, ProcessTrace, StartTraceW, TRACE_LEVEL_VERBOSE,
    WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::{GUID, PCWSTR, PWSTR};

use tracing::{debug, error, info, trace, warn};

use super::types::{RobloxAlert, RobloxExe, RobloxInstance};

fn format_win32_status(status: WIN32_ERROR) -> String {
    let io_err = io::Error::from_raw_os_error(status.0 as i32);
    format!("{} ({})", status.0, io_err)
}

pub struct ArEtwSubsystem {
    watcher: Option<RobloxEtwWatcher>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for ArEtwSubsystem {
    fn drop(&mut self) {
        let _ = self.watcher.take();
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

pub fn ArStartETWSubsystem() -> io::Result<(ArEtwSubsystem, std::sync::mpsc::Receiver<RobloxAlert>)>
{
    info!("ETW subsystem starting");
    let (watcher, rx) = RobloxEtwWatcher::start()?;
    info!("ETW subsystem started");

    Ok((
        ArEtwSubsystem {
            watcher: Some(watcher),
            worker: None,
        },
        rx,
    ))
}

struct State {
    sender: Sender<RobloxAlert>,
    instances: Mutex<HashMap<u32, RobloxInstance>>,
    is_waiting: Mutex<bool>,
}

pub struct RobloxEtwWatcher {
    stop: Arc<AtomicBool>,
    session: EtwSession,
    worker: Option<JoinHandle<()>>,
    state_ptr: *const State,
}

impl RobloxEtwWatcher {
    pub fn start() -> io::Result<(Self, Receiver<RobloxAlert>)> {
        info!("ETW watcher starting");
        let (tx, rx) = mpsc::channel::<RobloxAlert>();
        let stop = Arc::new(AtomicBool::new(false));

        let state = Arc::new(State {
            sender: tx,
            instances: Mutex::new(HashMap::new()),
            is_waiting: Mutex::new(false),
        });

        seed_from_process_snapshot(&state);
        emit_state_transition(&state, true);

        let session_name = "TITAN_ETW_ROBLOX".to_string();
        debug!(%session_name, "Starting ETW session");
        let session = EtwSession::start(&session_name)?;

        let consumer = EtwConsumer {
            name_w: session.name_w.clone(),
        };

        let stop2 = stop.clone();
        let state2 = state.clone();
        let worker = thread::spawn(move || {
            if let Err(e) = consumer.run(stop2, state2) {
                warn!("ETW consumer stopped with error: {e}");
            }
        });

        let state_ptr = Arc::into_raw(state);

        Ok((
            Self {
                stop,
                session,
                worker: Some(worker),
                state_ptr,
            },
            rx,
        ))
    }
}

impl Drop for RobloxEtwWatcher {
    fn drop(&mut self) {
        info!("ETW watcher stopping");
        self.stop.store(true, Ordering::SeqCst);
        if let Err(e) = self.session.stop() {
            warn!("ETW session stop during watcher drop failed: {e}");
        }
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
        unsafe {
            drop(Arc::from_raw(self.state_ptr));
        }
        info!("ETW watcher stopped");
    }
}

fn emit_state_transition(state: &Arc<State>, force_emit: bool) {
    let should_wait = {
        let inst = state.instances.lock().unwrap();
        !inst.is_empty()
    };

    let mut prev = state.is_waiting.lock().unwrap();
    if !force_emit && *prev == should_wait {
        return;
    }

    *prev = should_wait;
    let alert = if should_wait {
        RobloxAlert::SWait
    } else {
        RobloxAlert::SReady
    };
    trace!(?alert, "ETW state transition");
    let _ = state.sender.send(alert);
}

fn is_watched_exe_name(name: &str) -> Option<RobloxExe> {
    let base = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .trim()
        .to_ascii_lowercase();
    match base.as_str() {
        "robloxplayerbeta.exe" => Some(RobloxExe::RobloxPlayerBeta),
        "robloxplayerlauncher.exe" => Some(RobloxExe::RobloxPlayerLauncher),
        "robloxcrashhandler.exe" => Some(RobloxExe::RobloxCrashHandler),
        _ => None,
    }
}

fn seed_from_process_snapshot(state: &Arc<State>) {
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return,
        };

        let mut pe = PROCESSENTRY32W {
            dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snap, &mut pe).is_err() {
            let _ = CloseHandle(snap);
            return;
        }

        loop {
            let pid = pe.th32ProcessID;
            let name = widestr_to_string(&pe.szExeFile);
            if let Some(exe) = is_watched_exe_name(&name) {
                let path = query_process_path(pid).unwrap_or_else(|| name.clone());
                state
                    .instances
                    .lock()
                    .unwrap()
                    .insert(pid, RobloxInstance { exe, pid, path });
            }

            if Process32NextW(snap, &mut pe).is_err() {
                break;
            }
        }

        let _ = CloseHandle(snap);
    }
}

fn widestr_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn query_process_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 4096];
        let mut len: u32 = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut len as *mut u32,
        )
        .is_ok();
        let _ = CloseHandle(h);
        if !ok {
            return None;
        }
        buf.truncate(len as usize);
        Some(String::from_utf16_lossy(&buf))
    }
}

struct EtwSession {
    name_w: Vec<u16>,
    handle: CONTROLTRACE_HANDLE,
}

impl EtwSession {
    fn start(name: &str) -> io::Result<Self> {
        unsafe {
            let name_w = name.encode_utf16().chain([0]).collect::<Vec<u16>>();

            let props_size = mem::size_of::<EVENT_TRACE_PROPERTIES>();
            let name_bytes = name_w
                .len()
                .checked_mul(mem::size_of::<u16>())
                .ok_or_else(|| io::Error::other("ETW logger name size overflow"))?;
            let buf_size = props_size
                .checked_add(name_bytes)
                .ok_or_else(|| io::Error::other("ETW properties buffer size overflow"))?;
            let buffer_size_u32 = u32::try_from(buf_size)
                .map_err(|_| io::Error::other("ETW properties buffer exceeds u32"))?;
            let props_size_u32 =
                u32::try_from(props_size).map_err(|_| io::Error::other("props size overflow"))?;
            let mut buf = vec![0u8; buf_size];
            let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

            (*props).Wnode.BufferSize = buffer_size_u32;
            (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).LoggerNameOffset = props_size_u32;

            let name_ptr = buf.as_mut_ptr().add((*props).LoggerNameOffset as usize) as *mut u16;

            name_ptr.copy_from_nonoverlapping(name_w.as_ptr(), name_w.len());

            let pre_stop_status = ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                PCWSTR(name_ptr),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
            let preexisting_session_detected = pre_stop_status == WIN32_ERROR(0);
            info!(
                session_name = %name,
                pre_stop_control_trace_result = pre_stop_status.0,
                pre_stop_control_trace_status = %format_win32_status(pre_stop_status),
                preexisting_session_detected,
                "ETW pre-start ControlTraceW probe complete"
            );

            let mut handle = CONTROLTRACE_HANDLE::default();

            let mut start_status = StartTraceW(&mut handle, PCWSTR(name_ptr), props);
            let mut killed_existing_session = preexisting_session_detected;
            info!(
                session_name = %name,
                start_tracew_result = start_status.0,
                start_tracew_status = %format_win32_status(start_status),
                "ETW StartTraceW returned"
            );

            if start_status == WIN32_ERROR(ERROR_ALREADY_EXISTS.0) {
                warn!("ETW session already exists; stopping previous session");
                let stop_existing_status = ControlTraceW(
                    CONTROLTRACE_HANDLE { Value: 0 },
                    PCWSTR(name_ptr),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
                killed_existing_session = stop_existing_status == WIN32_ERROR(0);
                info!(
                    session_name = %name,
                    stop_existing_control_trace_result = stop_existing_status.0,
                    stop_existing_control_trace_status = %format_win32_status(stop_existing_status),
                    killed_existing_session,
                    "ETW existing session stop attempt complete"
                );
                start_status = StartTraceW(&mut handle, PCWSTR(name_ptr), props);
                info!(
                    session_name = %name,
                    start_tracew_retry_result = start_status.0,
                    start_tracew_retry_status = %format_win32_status(start_status),
                    "ETW StartTraceW retry returned"
                );
            }

            if start_status != WIN32_ERROR(0) {
                error!(
                    session_name = %name,
                    start_tracew_result = start_status.0,
                    start_tracew_status = %format_win32_status(start_status),
                    preexisting_session_detected,
                    killed_existing_session,
                    "StartTraceW failed"
                );
                return Err(io::Error::other(format!(
                    "StartTraceW failed: {}",
                    format_win32_status(start_status)
                )));
            }

            let provider = kernel_process_provider_guid();

            let params = ENABLE_TRACE_PARAMETERS {
                Version: ENABLE_TRACE_PARAMETERS_VERSION,
                ..Default::default()
            };

            let enable_status = EnableTraceEx2(
                handle,
                &provider,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_VERBOSE as u8,
                u64::MAX,
                0,
                0,
                Some(&params),
            );
            info!(
                session_name = %name,
                enable_trace_ex2_result = enable_status.0,
                enable_trace_ex2_status = %format_win32_status(enable_status),
                preexisting_session_detected,
                killed_existing_session,
                "EnableTraceEx2 returned"
            );

            if enable_status != WIN32_ERROR(0) {
                error!(
                    session_name = %name,
                    enable_trace_ex2_result = enable_status.0,
                    enable_trace_ex2_status = %format_win32_status(enable_status),
                    "EnableTraceEx2 failed"
                );
                let stop_on_error_status =
                    ControlTraceW(handle, PCWSTR(name_ptr), props, EVENT_TRACE_CONTROL_STOP);
                warn!(
                    session_name = %name,
                    stop_on_error_result = stop_on_error_status.0,
                    stop_on_error_status = %format_win32_status(stop_on_error_status),
                    "ControlTraceW stop issued after EnableTraceEx2 failure"
                );

                return Err(io::Error::other(format!(
                    "EnableTraceEx2 failed: {}",
                    format_win32_status(enable_status)
                )));
            }

            info!(
                session_name = %name,
                preexisting_session_detected,
                killed_existing_session,
                "ETW session started"
            );
            Ok(Self { name_w, handle })
        }
    }

    fn stop(&self) -> io::Result<()> {
        unsafe {
            let props_size = mem::size_of::<EVENT_TRACE_PROPERTIES>();
            let name_bytes = self
                .name_w
                .len()
                .checked_mul(mem::size_of::<u16>())
                .ok_or_else(|| io::Error::other("ETW logger name size overflow"))?;
            let buf_size = props_size
                .checked_add(name_bytes)
                .ok_or_else(|| io::Error::other("ETW properties buffer size overflow"))?;
            let buffer_size_u32 = u32::try_from(buf_size)
                .map_err(|_| io::Error::other("ETW properties buffer exceeds u32"))?;
            let props_size_u32 =
                u32::try_from(props_size).map_err(|_| io::Error::other("props size overflow"))?;
            let mut buf = vec![0u8; buf_size];
            let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

            (*props).Wnode.BufferSize = buffer_size_u32;
            (*props).LoggerNameOffset = props_size_u32;

            let name_ptr = buf.as_mut_ptr().add((*props).LoggerNameOffset as usize) as *mut u16;

            name_ptr.copy_from_nonoverlapping(self.name_w.as_ptr(), self.name_w.len());

            let stop_status = ControlTraceW(
                self.handle,
                PCWSTR(name_ptr),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
            info!(
                stop_control_trace_result = stop_status.0,
                stop_control_trace_status = %format_win32_status(stop_status),
                "ControlTraceW stop returned"
            );
            if stop_status != WIN32_ERROR(0) {
                return Err(io::Error::other(format!(
                    "ControlTraceW stop failed: {}",
                    format_win32_status(stop_status)
                )));
            }

            info!("ETW session stopped");
            Ok(())
        }
    }
}

struct EtwConsumer {
    name_w: Vec<u16>,
}

impl EtwConsumer {
    fn run(&self, stop: Arc<AtomicBool>, state: Arc<State>) -> io::Result<()> {
        unsafe {
            info!("ETW consumer starting");
            let state_ptr = Arc::as_ptr(&state) as *mut c_void;

            let mut log = EVENT_TRACE_LOGFILEW {
                LoggerName: PWSTR(self.name_w.as_ptr() as *mut u16),
                Anonymous1: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW_0 {
                    ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME
                        | PROCESS_TRACE_MODE_EVENT_RECORD,
                },
                Context: state_ptr,
                Anonymous2: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW_1 {
                    EventRecordCallback: Some(etw_event_record_callback),
                },
                ..Default::default()
            };

            let trace_handle = OpenTraceW(&mut log);
            if trace_handle.Value == u64::MAX {
                let open_err = GetLastError();
                error!(
                    open_tracew_result = open_err.0,
                    open_tracew_status = %format_win32_status(open_err),
                    "OpenTraceW failed"
                );
                return Err(io::Error::other(format!(
                    "OpenTraceW failed: {}",
                    format_win32_status(open_err)
                )));
            }
            info!(open_tracew_result = 0, "OpenTraceW succeeded");

            let _ = stop;
            let process_status = ProcessTrace(&[trace_handle], None, None);
            if process_status != WIN32_ERROR(0) {
                let close_status = CloseTrace(trace_handle);
                error!(
                    process_trace_result = process_status.0,
                    process_trace_status = %format_win32_status(process_status),
                    close_trace_result = close_status.0,
                    close_trace_status = %format_win32_status(close_status),
                    "ProcessTrace failed"
                );
                return Err(io::Error::other(format!(
                    "ProcessTrace failed: {}",
                    format_win32_status(process_status)
                )));
            }
            info!(
                process_trace_result = process_status.0,
                process_trace_status = %format_win32_status(process_status),
                "ProcessTrace returned"
            );

            let close_status = CloseTrace(trace_handle);
            info!(
                close_trace_result = close_status.0,
                close_trace_status = %format_win32_status(close_status),
                "CloseTrace returned"
            );
            info!("ETW consumer stopped");
            Ok(())
        }
    }
}

fn kernel_process_provider_guid() -> GUID {
    GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716)
}

unsafe extern "system" fn etw_event_record_callback(event: *mut EVENT_RECORD) {
    if event.is_null() {
        return;
    }

    let event = unsafe { &*event };

    if event.EventHeader.ProviderId != kernel_process_provider_guid() {
        return;
    }

    let id = event.EventHeader.EventDescriptor.Id;
    let is_start = id == 1;
    let is_end = id == 2;
    if !is_start && !is_end {
        return;
    }

    let state = event.UserContext as *const State;
    if state.is_null() {
        return;
    }

    let state = unsafe { &*state };

    let pid = tdh_get_u32(event, "ProcessId")
        .or_else(|| tdh_get_u32(event, "ProcessID"))
        .unwrap_or(event.EventHeader.ProcessId);

    if pid == 0 {
        return;
    }

    if is_start {
        let Some((exe, path)) = classify_roblox_process(event, pid) else {
            return;
        };

        let instance = RobloxInstance { exe, pid, path };

        let mut map = state.instances.lock().unwrap();
        let was_empty = map.is_empty();
        if map.insert(pid, instance.clone()).is_none() {
            let tracked_instances = map.len();
            info!(
                pid = instance.pid,
                exe = ?instance.exe,
                path = %instance.path,
                tracked_instances,
                "ETW detected Roblox process start"
            );
            let _ = state.sender.send(RobloxAlert::ProcessStart { instance });
            if was_empty {
                let mut prev = state.is_waiting.lock().unwrap();
                if !*prev {
                    *prev = true;
                    let _ = state.sender.send(RobloxAlert::SWait);
                }
            }
        }
        return;
    }

    if is_end {
        let mut map = state.instances.lock().unwrap();
        let removed = map.remove(&pid);
        let is_now_empty = map.is_empty();
        let tracked_instances = map.len();
        drop(map);

        if let Some(instance) = removed {
            info!(
                pid = instance.pid,
                exe = ?instance.exe,
                path = %instance.path,
                tracked_instances,
                "ETW detected Roblox process stop"
            );
            let _ = state.sender.send(RobloxAlert::ProcessStop { instance });
        }
        if is_now_empty {
            let mut prev = state.is_waiting.lock().unwrap();
            if *prev {
                *prev = false;
                let _ = state.sender.send(RobloxAlert::SReady);
            }
        }
    }
}

fn tdh_get_u32(event: &EVENT_RECORD, prop_name: &str) -> Option<u32> {
    use windows::Win32::System::Diagnostics::Etw::{TdhGetProperty, TdhGetPropertySize};

    let name_w: Vec<u16> = prop_name.encode_utf16().chain([0]).collect();
    let desc = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name_w.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let descs = [desc];

    let mut size: u32 = 0;
    let status =
        unsafe { TdhGetPropertySize(event as *const _, None, &descs, &mut size as *mut u32) };
    if status != 0 || size < 4 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let status = unsafe { TdhGetProperty(event as *const _, None, &descs, &mut buf) };
    if status != 0 || buf.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

fn classify_roblox_process(event: &EVENT_RECORD, pid: u32) -> Option<(RobloxExe, String)> {
    let image = tdh_get_string(event, "ImageFileName")
        .or_else(|| tdh_get_string(event, "ProcessName"))
        .or_else(|| tdh_get_string(event, "ImageName"))
        .unwrap_or_default();

    let cmd = tdh_get_string(event, "CommandLine").unwrap_or_default();

    let path = query_process_path(pid)
        .or_else(|| {
            if !cmd.is_empty() {
                Some(cmd.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| image.clone());

    let exe = is_watched_exe_name(&path)
        .or_else(|| is_watched_exe_name(&cmd))
        .or_else(|| is_watched_exe_name(&image))?;

    let out = if path.is_empty() {
        if cmd.is_empty() { image } else { cmd }
    } else {
        path
    };

    if out.is_empty() {
        None
    } else {
        Some((exe, out))
    }
}

fn tdh_get_string(event: &EVENT_RECORD, prop_name: &str) -> Option<String> {
    use windows::Win32::System::Diagnostics::Etw::{TdhGetProperty, TdhGetPropertySize};

    let name_w: Vec<u16> = prop_name.encode_utf16().chain([0]).collect();
    let desc = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name_w.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let descs = [desc];

    let mut size: u32 = 0;
    let status = unsafe { TdhGetPropertySize(event as *const _, None, &descs, &mut size) };
    if status != 0 || size == 0 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let status = unsafe { TdhGetProperty(event as *const _, None, &descs, &mut buf) };
    if status != 0 || buf.is_empty() {
        return None;
    }

    if buf.len() >= 2 && buf.len().is_multiple_of(2) {
        let odd_zeroes = buf.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
        let pairs = buf.len() / 2;
        if odd_zeroes.saturating_mul(2) >= pairs {
            let mut u16s = Vec::with_capacity(pairs);
            for c in buf.chunks_exact(2) {
                u16s.push(u16::from_le_bytes([c[0], c[1]]));
            }
            if let Some(end) = u16s.iter().position(|&c| c == 0) {
                u16s.truncate(end);
            }
            let s = String::from_utf16_lossy(&u16s).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }

    let s = String::from_utf8_lossy(&buf)
        .trim_matches('\0')
        .trim()
        .to_string();

    if s.is_empty() { None } else { Some(s) }
}
