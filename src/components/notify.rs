use std::sync::mpsc;
use std::time::Duration;

use windows::{
    Data::Xml::Dom::XmlDocument,
    Foundation::TypedEventHandler,
    UI::Notifications::{
        ToastActivatedEventArgs, ToastDismissedEventArgs, ToastFailedEventArgs, ToastNotification,
        ToastNotificationManager,
    },
    Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx},
    core::{HSTRING, IInspectable, Interface},
};

use tracing::{error, info, warn};

const AUMID: &str = "TITAN.Spoofer";
const TOAST_TIMEOUT_SECS: u64 = 30;

#[derive(Debug)]
enum ToastResult {
    Spoof,
    Ignore,
    Failed,
    Timeout,
}

pub fn ask_user_to_spoof() -> bool {
    match show_toast() {
        Ok(ToastResult::Spoof) => true,
        Ok(ToastResult::Ignore) => false,
        Ok(ToastResult::Timeout) => {
            warn!("Toast timed out without user interaction.");
            false
        }
        Ok(ToastResult::Failed) => {
            warn!("Toast failed.");
            false
        }
        Err(e) => {
            error!("Toast system error: {e}");
            false
        }
    }
}

fn show_toast() -> anyhow::Result<ToastResult> {
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
    }
    info!("Toast subsystem COM initialized (MTA).");

    let xml = r#"
<toast launch="action=spoof">
    <visual>
        <binding template="ToastGeneric">
            <text>TITAN Spoofer</text>
            <text>Roblox has closed. Spoof hardware identifiers?</text>
        </binding>
    </visual>
    <actions>
        <action content="Spoof Now" arguments="spoof" activationType="foreground"/>
        <action content="Ignore" arguments="ignore" activationType="foreground"/>
    </actions>
</toast>
"#;

    let doc = XmlDocument::new()?;
    doc.LoadXml(&HSTRING::from(xml))?;

    let toast = ToastNotification::CreateToastNotification(&doc)?;

    let (tx, rx) = mpsc::channel::<ToastResult>();

    let tx_activated = tx.clone();
    toast.Activated(&TypedEventHandler::<ToastNotification, IInspectable>::new(
        move |_sender, args| {
            let inspectable = match &*args {
                Some(v) => v,
                None => {
                    tx_activated.send(ToastResult::Failed).ok();
                    return Ok(());
                }
            };

            let activation: ToastActivatedEventArgs = match inspectable.cast() {
                Ok(a) => a,
                Err(e) => {
                    warn!("Toast activation cast failed: {e}");
                    tx_activated.send(ToastResult::Failed).ok();
                    return Ok(());
                }
            };

            let arg = activation.Arguments()?;
            if arg == "spoof" {
                tx_activated.send(ToastResult::Spoof).ok();
            } else {
                tx_activated.send(ToastResult::Ignore).ok();
            }

            Ok(())
        },
    ))?;

    let tx_dismissed = tx.clone();
    toast.Dismissed(&TypedEventHandler::<
        ToastNotification,
        ToastDismissedEventArgs,
    >::new(move |_sender, _args| {
        tx_dismissed.send(ToastResult::Ignore).ok();
        Ok(())
    }))?;

    let tx_failed = tx.clone();
    toast.Failed(
        &TypedEventHandler::<ToastNotification, ToastFailedEventArgs>::new(
            move |_sender, _args| {
                warn!("Toast notification failure callback invoked.");
                tx_failed.send(ToastResult::Failed).ok();
                Ok(())
            },
        ),
    )?;

    let notifier = match ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID))
    {
        Ok(n) => {
            info!("Using AUMID-based toast notifier.");
            n
        }
        Err(e) => {
            warn!("AUMID notifier failed: {e}. Falling back to default notifier.");
            ToastNotificationManager::CreateToastNotifier()?
        }
    };

    notifier.Show(&toast)?;
    info!("Toast Show() returned success.");

    match rx.recv_timeout(Duration::from_secs(TOAST_TIMEOUT_SECS)) {
        Ok(result) => Ok(result),
        Err(_) => Ok(ToastResult::Timeout),
    }
}
