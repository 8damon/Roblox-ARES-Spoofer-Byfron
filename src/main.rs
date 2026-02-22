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
use tracing::error;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::Console::{AllocConsole, SetConsoleTitleW};
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
