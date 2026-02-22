#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

pub mod components;
mod engine;
mod etw;
mod modules;
mod setup;

use crate::{
    components::tracing::{ArSetConsoleTracingAnsi, ArTracing},
    modules::{
        PE::headers::{ArWipeHeaders, TRUE},
        clean::kill::ArKillProcess,
    },
    setup::{
        access::ArAccessCheck,
        setup::{ArConfig, ArRunSetup},
    },
};

use std::ffi::c_void;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use windows::Win32::Foundation::{CloseHandle, HINSTANCE};
use windows::Win32::System::Console::{AllocConsole, SetConsoleTitleW};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
use windows::core::PCWSTR;

#[unsafe(no_mangle)]
unsafe extern "system" fn TSRS_CALLBACK(_hinst: HINSTANCE, reason: u32, _reserved: *mut c_void) {
    if reason == 1 {
        ArKillProcess("RobloxPlayerBeta.exe");
    }
}

#[used]
#[cfg_attr(target_env = "msvc", unsafe(link_section = ".CRT$XLB"))]
static TLS_ENTRY: unsafe extern "system" fn(HINSTANCE, u32, *mut c_void) = TSRS_CALLBACK;

fn main() {
    components::tracing::ArSetConsoleTracingMuted(true);
    ArSetConsoleTracingAnsi(true);
    ArEnsureWorkingDirectoryAtExeDir();

    let _ = ArAccessCheck();

    let cfg = match ArRunSetup() {
        Ok(c) => c,
        Err(e) => {
            error!("Initialization failed: {e}");
            std::process::exit(1);
        }
    };

    if cfg.general.require_rerun_after_setup {
        if cfg.runtime.run_in_background {
            eprintln!("Setup finished. Background mode was started via scheduled task.");
        } else {
            eprintln!("Setup finished. Re-run this executable to continue.");
        }
        std::process::exit(0);
    }

    ArRunConfiguredEngine(cfg);
}

fn ArEnsureWorkingDirectoryAtExeDir() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let Some(dir) = exe.parent() else {
        return;
    };
    let _ = std::env::set_current_dir(dir);
}

pub(crate) fn ArRunConfiguredEngine(cfg: ArConfig) {
    if cfg.runtime.spoof_on_file_run {
        ArAttachRuntimeConsole();
        components::tracing::ArSetConsoleTracingMuted(false);
        ArSetConsoleTracingAnsi(false);
    } else {
        components::tracing::ArSetConsoleTracingMuted(true);
        ArSetConsoleTracingAnsi(true);
    }
    ArTracing();
    ArEnforceSingleInstance();

    let _veh_guard = components::VEH::ArVehGuard::start();
    let _perf_monitor = components::performance::ArPerformanceMonitor::start();

    unsafe {
        let _ = ArWipeHeaders(TRUE);
    }

    if let Err(e) = engine::TrsEngine::new(cfg).run() {
        error!("Engine failure: {e}");
        std::process::exit(1);
    }
}

fn ArAttachRuntimeConsole() {
    unsafe {
        let _ = AllocConsole();
        let title: Vec<u16> = "TRS Runtime Logs".encode_utf16().chain(Some(0)).collect();
        let _ = SetConsoleTitleW(PCWSTR(title.as_ptr()));
    }
}

fn ArEnforceSingleInstance() {
    let current_pid = std::process::id();
    let image_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "aresrs.exe".to_string());

    let initial_targets = ArListOtherProcessIdsByImageName(&image_name, current_pid);
    if initial_targets.is_empty() {
        info!(
            current_pid,
            image_name = %image_name,
            "Single-instance guard: no existing instances detected"
        );
        return;
    }

    info!(
        current_pid,
        image_name = %image_name,
        target_count = initial_targets.len(),
        target_pids = ?initial_targets,
        "Single-instance guard: terminating existing instances"
    );

    let mut termination_failed = Vec::new();
    for pid in &initial_targets {
        unsafe {
            match OpenProcess(PROCESS_TERMINATE, false, *pid) {
                Ok(h) => {
                    let terminate_ok = TerminateProcess(h, 0).is_ok();
                    let _ = CloseHandle(h);
                    if !terminate_ok {
                        termination_failed.push(*pid);
                    }
                }
                Err(_) => termination_failed.push(*pid),
            }
        }
    }

    let wait_deadline = Instant::now() + Duration::from_secs(6);
    let mut survivors = initial_targets.clone();
    while Instant::now() < wait_deadline {
        survivors = ArListOtherProcessIdsByImageName(&image_name, current_pid)
            .into_iter()
            .filter(|pid| initial_targets.contains(pid))
            .collect();
        if survivors.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }

    if !termination_failed.is_empty() || !survivors.is_empty() {
        warn!(
            current_pid,
            image_name = %image_name,
            termination_failed = ?termination_failed,
            survivors = ?survivors,
            "Single-instance guard completed with unresolved processes"
        );
    } else {
        info!(
            current_pid,
            image_name = %image_name,
            terminated_pids = ?initial_targets,
            "Single-instance guard completed successfully"
        );
    }
}

fn ArListOtherProcessIdsByImageName(image_name: &str, current_pid: u32) -> Vec<u32> {
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut matches = Vec::new();

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                let pid = entry.th32ProcessID;

                if pid != current_pid && name.eq_ignore_ascii_case(image_name) {
                    matches.push(pid);
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        matches
    }
}
