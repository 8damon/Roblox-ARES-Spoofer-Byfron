use tracing::{error, info, warn};
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::*;
use windows::Win32::System::Variant::VARIANT;
use windows::core::Interface;
use windows::core::Result;

const TASK_NAME: &str = "ARESRS-Startup";
const TASK_AUTHOR: &str = "ARESRS";

fn ArCurrentTaskUser() -> Option<String> {
    let username = std::env::var("USERNAME").ok()?;
    if username.trim().is_empty() {
        return None;
    }

    let domain = std::env::var("USERDOMAIN").ok();
    match domain {
        Some(d) if !d.trim().is_empty() => Some(format!("{d}\\{username}")),
        _ => Some(username),
    }
}

pub fn ArSyncStartupTask(enable: bool) {
    if enable {
        if let Err(e) = ArTaskInstall() {
            error!("Failed to install startup scheduled task: {e}");
        }
    } else if let Err(e) = ArTaskUninstall() {
        warn!("Failed to remove startup scheduled task: {e}");
    }
}

pub fn ArStartStartupTaskNow() {
    if let Err(e) = ArTaskRunNow() {
        warn!("Failed to start startup scheduled task immediately: {e}");
    }
}

pub fn ArTaskInstall() -> Result<()> {
    unsafe {
        let initialized = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();

        let result = (|| -> Result<()> {
            let service: ITaskService =
                CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
            let empty = VARIANT::default();
            service.Connect(&empty, &empty, &empty, &empty)?;

            let root = service.GetFolder(&windows::core::BSTR::from("\\"))?;
            let task_name = windows::core::BSTR::from(TASK_NAME);

            let _ = root.DeleteTask(&task_name, 0);

            let task_def = service.NewTask(0)?;

            let reg_info = task_def.RegistrationInfo()?;
            reg_info.SetAuthor(&windows::core::BSTR::from(TASK_AUTHOR))?;

            let principal = task_def.Principal()?;
            let task_user = ArCurrentTaskUser().map(windows::core::BSTR::from);
            if let Some(user) = task_user.as_ref() {
                principal.SetUserId(user)?;
            }
            principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)?;
            principal.SetRunLevel(TASK_RUNLEVEL_HIGHEST)?;

            let settings = task_def.Settings()?;
            settings.SetEnabled(VARIANT_BOOL::from(true))?;
            settings.SetStartWhenAvailable(VARIANT_BOOL::from(true))?;
            settings.SetDisallowStartIfOnBatteries(VARIANT_BOOL::from(false))?;
            settings.SetStopIfGoingOnBatteries(VARIANT_BOOL::from(false))?;

            let triggers = task_def.Triggers()?;
            let trigger = triggers.Create(TASK_TRIGGER_LOGON)?;
            let logon: ILogonTrigger = trigger.cast()?;
            if let Some(user) = task_user.as_ref() {
                logon.SetUserId(user)?;
            }
            logon.SetEnabled(VARIANT_BOOL::from(true))?;

            let exe = std::env::current_exe()?;
            let exe_str = exe.to_string_lossy().to_string();
            let workdir = exe
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| ".".to_string());

            let actions = task_def.Actions()?;
            let action = actions.Create(TASK_ACTION_EXEC)?;
            let exec: IExecAction = action.cast()?;
            exec.SetPath(&windows::core::BSTR::from(exe_str))?;
            exec.SetWorkingDirectory(&windows::core::BSTR::from(workdir))?;

            root.RegisterTaskDefinition(
                &task_name,
                &task_def,
                TASK_CREATE_OR_UPDATE.0,
                &task_user
                    .as_ref()
                    .map(|u| VARIANT::from(u.clone()))
                    .unwrap_or_default(),
                &empty,
                TASK_LOGON_INTERACTIVE_TOKEN,
                &empty,
            )?;

            info!("Startup scheduled task installed/updated");
            Ok(())
        })();

        if initialized {
            CoUninitialize();
        }
        result
    }
}

pub fn ArTaskUninstall() -> Result<()> {
    unsafe {
        let initialized = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();

        let result = (|| -> Result<()> {
            let service: ITaskService =
                CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
            let empty = VARIANT::default();
            service.Connect(&empty, &empty, &empty, &empty)?;

            let root = service.GetFolder(&windows::core::BSTR::from("\\"))?;
            let task_name = windows::core::BSTR::from(TASK_NAME);

            let _ = root.DeleteTask(&task_name, 0);
            info!("Startup scheduled task removed");

            Ok(())
        })();

        if initialized {
            CoUninitialize();
        }
        result
    }
}

pub fn ArTaskRunNow() -> Result<()> {
    unsafe {
        let initialized = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();

        let result = (|| -> Result<()> {
            let service: ITaskService =
                CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
            let empty = VARIANT::default();
            service.Connect(&empty, &empty, &empty, &empty)?;

            let root = service.GetFolder(&windows::core::BSTR::from("\\"))?;
            let task_name = windows::core::BSTR::from(TASK_NAME);
            let task = root.GetTask(&task_name)?;

            let _ = task.Run(&empty)?;
            info!("Startup scheduled task started immediately");
            Ok(())
        })();

        if initialized {
            CoUninitialize();
        }
        result
    }
}
