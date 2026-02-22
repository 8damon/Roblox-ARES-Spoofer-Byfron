use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::ProcessStatus::{
    EmptyWorkingSet, GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessIoCounters, GetProcessTimes, IO_COUNTERS,
};
use windows::Win32::System::WindowsProgramming::QueryProcessCycleTime;

pub struct ArPerformanceMonitor {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

struct PerfConfig {
    log_interval: Duration,
    sample_interval: Duration,
    trim_min_interval: Duration,
    trim_ws_threshold_bytes: u64,
}

impl PerfConfig {
    fn from_env() -> Self {
        let log_secs = env_u64("TSRS_PERF_LOG_SECS", 30).max(5);
        let sample_secs = env_u64("TSRS_PERF_SAMPLE_SECS", 5).max(1);
        let trim_secs = env_u64("TSRS_PERF_TRIM_SECS", 300).max(30);
        let trim_ws_mb = env_u64("TSRS_PERF_TRIM_WS_MB", 450).max(64);

        Self {
            log_interval: Duration::from_secs(log_secs),
            sample_interval: Duration::from_secs(sample_secs),
            trim_min_interval: Duration::from_secs(trim_secs),
            trim_ws_threshold_bytes: trim_ws_mb * 1024 * 1024,
        }
    }
}

impl ArPerformanceMonitor {
    pub fn start() -> Self {
        let cfg = PerfConfig::from_env();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();

        let worker = thread::spawn(move || {
            let pid = unsafe { GetCurrentProcessId() };
            let mut last_log = instant_minus(cfg.log_interval);
            let mut last_trim = instant_minus(cfg.trim_min_interval);

            info!(
                pid,
                log_interval_s = cfg.log_interval.as_secs(),
                trim_interval_s = cfg.trim_min_interval.as_secs(),
                trim_ws_mb = cfg.trim_ws_threshold_bytes / (1024 * 1024),
                "Performance monitor started"
            );

            while !stop2.load(Ordering::Relaxed) {
                let mem = read_memory_counters();

                if let Some(mem_now) = mem.as_ref()
                    && mem_now.working_set_size >= cfg.trim_ws_threshold_bytes
                    && last_trim.elapsed() >= cfg.trim_min_interval
                {
                    if trim_working_set() {
                        debug!(
                            ws_bytes = mem_now.working_set_size,
                            "Working-set trim requested"
                        );
                    }
                    last_trim = Instant::now();
                }

                if last_log.elapsed() >= cfg.log_interval {
                    log_perf_snapshot(mem);
                    last_log = Instant::now();
                }

                thread::sleep(cfg.sample_interval);
            }

            info!("Performance monitor stopped");
        });

        Self {
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for ArPerformanceMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn trim_working_set() -> bool {
    unsafe { EmptyWorkingSet(GetCurrentProcess()).is_ok() }
}

fn log_perf_snapshot(mem_pre: Option<MemoryCounters>) {
    let mem = mem_pre.or_else(read_memory_counters);
    let io = read_io_counters();
    let cpu = read_cpu_counters();

    if let (Some(mem), Some(io), Some(cpu)) = (mem, io, cpu) {
        let consumption = mem.private_bytes.saturating_add(io.WriteTransferCount);

        info!(
            ws_bytes = mem.working_set_size,
            peak_ws_bytes = mem.peak_working_set_size,
            private_bytes = mem.private_bytes,
            pagefile_bytes = mem.pagefile_usage,
            cpu_cycles = cpu.cycle_time,
            cpu_kernel_100ns = cpu.kernel_100ns,
            cpu_user_100ns = cpu.user_100ns,
            io_read_bytes = io.ReadTransferCount,
            io_write_bytes = io.WriteTransferCount,
            io_other_bytes = io.OtherTransferCount,
            consumption_score = consumption,
            "Performance snapshot"
        );
    } else {
        warn!("Performance snapshot incomplete");
    }
}

struct MemoryCounters {
    working_set_size: u64,
    peak_working_set_size: u64,
    private_bytes: u64,
    pagefile_usage: u64,
}

fn read_memory_counters() -> Option<MemoryCounters> {
    unsafe {
        let process = GetCurrentProcess();
        let mut pmc = PROCESS_MEMORY_COUNTERS_EX {
            cb: mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            ..Default::default()
        };

        if GetProcessMemoryInfo(process, &mut pmc as *mut _ as *mut _, pmc.cb).is_err() {
            return None;
        }

        Some(MemoryCounters {
            working_set_size: pmc.WorkingSetSize as u64,
            peak_working_set_size: pmc.PeakWorkingSetSize as u64,
            private_bytes: pmc.PrivateUsage as u64,
            pagefile_usage: pmc.PagefileUsage as u64,
        })
    }
}

fn read_io_counters() -> Option<IO_COUNTERS> {
    unsafe {
        let process = GetCurrentProcess();
        let mut io = IO_COUNTERS::default();
        if GetProcessIoCounters(process, &mut io).is_err() {
            return None;
        }
        Some(io)
    }
}

struct CpuCounters {
    cycle_time: u64,
    kernel_100ns: u64,
    user_100ns: u64,
}

fn read_cpu_counters() -> Option<CpuCounters> {
    unsafe {
        let process = GetCurrentProcess();

        let mut cycles = 0u64;
        if QueryProcessCycleTime(process, &mut cycles).is_err() {
            return None;
        }

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();

        if GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user).is_err() {
            return None;
        }

        Some(CpuCounters {
            cycle_time: cycles,
            kernel_100ns: filetime_to_u64(kernel),
            user_100ns: filetime_to_u64(user),
        })
    }
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

fn instant_minus(duration: Duration) -> Instant {
    Instant::now()
        .checked_sub(duration)
        .unwrap_or_else(Instant::now)
}
