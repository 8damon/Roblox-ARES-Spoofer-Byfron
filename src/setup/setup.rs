use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::scheduler::{ArStartStartupTaskNow, ArSyncStartupTask};
use windows::Win32::System::Console::{AllocConsole, FreeConsole, SetConsoleTitleW};
use windows::core::PCWSTR;

const CONFIG_FILENAME: &str = "ares-rs-config.toml";
const SETUP_ASCII_BANNER: &str = r#"
      ><       ><<<<<<<    ><<<<<<<<  ><< <<       ><<<<<<<      ><< <<  
     >< <<     ><<    ><<  ><<      ><<    ><<     ><<    ><<  ><<    ><<
    ><  ><<    ><<    ><<  ><<       ><<           ><<    ><<   ><<      
   ><<   ><<   >< ><<      ><<<<<<     ><<         >< ><<         ><<    
  ><<<<<< ><<  ><<  ><<    ><<            ><<      ><<  ><<          ><< 
 ><<       ><< ><<    ><<  ><<      ><<    ><<     ><<    ><<  ><<    ><<
><<         ><<><<      ><<><<<<<<<<  ><< <<       ><<      ><<  ><< <<  
                                                                         
                    https://hub.titansoftwork.com
                                v2.0.0
"#;

#[derive(Serialize, Deserialize, Debug)]
pub struct ArConfig {
    pub general: General,
    pub runtime: Runtime,
    #[serde(default)]
    pub spoofing: Spoofing,
    pub bootstrapper: Bootstrapper,
    pub update: Update,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct General {
    pub completed_setup: bool,
    #[serde(default)]
    pub require_rerun_after_setup: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Runtime {
    pub run_on_startup: bool,
    pub run_in_background: bool,
    pub spoof_on_file_run: bool,
    pub spoof_on_roblox_close: SpoofMode,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Spoofing {
    #[serde(default = "default_true", alias = "clean_and_reinstall")]
    pub clean_and_reinstall: bool,
    #[serde(default = "default_true", alias = "spoof_connected_adapters")]
    pub spoof_connected_adapters: bool,
}

impl Default for Spoofing {
    fn default() -> Self {
        Self {
            clean_and_reinstall: true,
            spoof_connected_adapters: true,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SpoofMode {
    Silent,
    Notify,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Bootstrapper {
    pub use_bootstrapper: bool,
    pub path: String,
    pub custom_cli_flag: String,
    pub override_install: bool,
    #[serde(default = "default_true", alias = "OPEN_ROBLOX_AFTER_SPOOF")]
    pub open_roblox_after_spoof: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Update {
    pub enabled: bool,
    pub auto_install: bool,
    pub channel: String,
    pub asset_name: String,
}

impl Default for ArConfig {
    fn default() -> Self {
        Self {
            general: General {
                completed_setup: false,
                require_rerun_after_setup: false,
            },
            runtime: Runtime {
                run_on_startup: false,
                run_in_background: false,
                spoof_on_file_run: false,
                spoof_on_roblox_close: SpoofMode::Silent,
            },
            spoofing: Spoofing {
                clean_and_reinstall: true,
                spoof_connected_adapters: true,
            },
            bootstrapper: Bootstrapper {
                use_bootstrapper: false,
                path: String::new(),
                custom_cli_flag: String::new(),
                override_install: false,
                open_roblox_after_spoof: true,
            },
            update: Update {
                enabled: true,
                auto_install: false,
                channel: "releases".into(),
                asset_name: String::new(),
            },
        }
    }
}

fn default_true() -> bool {
    true
}

pub fn ArRunSetup() -> io::Result<ArConfig> {
    let config_path = config_path_next_to_exe()?;
    info!(config_path = %config_path.to_string_lossy(), "Setup/config bootstrap started");

    let mut config = load_or_create_config(&config_path)?;
    info!(
        completed_setup = config.general.completed_setup,
        require_rerun_after_setup = config.general.require_rerun_after_setup,
        run_on_startup = config.runtime.run_on_startup,
        run_in_background = config.runtime.run_in_background,
        spoof_on_file_run = config.runtime.spoof_on_file_run,
        "Configuration loaded"
    );
    let mut ran_setup_wizard = false;

    if !config.general.completed_setup {
        info!("Running initial setup wizard");
        attach_setup_console();
        println!("{}", SETUP_ASCII_BANNER);
        println!("[=== INITIAL SETUP ===]");

        run_setup_questions(&mut config)?;

        config.general.completed_setup = true;
        config.general.require_rerun_after_setup = true;
        save_config(&config_path, &config)?;
        ran_setup_wizard = true;

        println!();
        println!("[=== SETUP COMPLETED ===]");
        println!("If you want to redo setup later:");
        println!("1) Open `{}`", config_path.to_string_lossy());
        println!("2) Change `completed_setup = true` to `completed_setup = false`");
        println!("3) Re-run this file to start the setup wizard again");
        if config.runtime.run_in_background {
            println!("Background mode will be started automatically after setup exits.");
            println!("You do not need to re-run this file.\n");
        } else {
            println!("Please re-run this file now to start the actual program.\n");
        }
        pause_before_exit()?;
        info!("Setup completed");
        detach_setup_console();
    }

    if ran_setup_wizard {
        sync_startup_task_if_needed(&config);
        if config.runtime.run_in_background {
            info!("Setup requested immediate background startup task run");
            ArStartStartupTaskNow();
        }
        return Ok(config);
    }

    let mut config_changed = enforce_mode_exclusivity(&mut config);
    sync_startup_task_if_needed(&config);

    if config.general.require_rerun_after_setup {
        config.general.require_rerun_after_setup = false;
        config_changed = true;
        info!("Cleared require_rerun_after_setup after successful rerun");
    }

    if config_changed {
        save_config(&config_path, &config)?;
        info!(config_path = %config_path.to_string_lossy(), "Persisted normalized configuration");
    }

    Ok(config)
}

fn config_path_next_to_exe() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| io::Error::other("Executable has no parent directory"))?;
    Ok(dir.join(CONFIG_FILENAME))
}

fn load_or_create_config(path: &Path) -> io::Result<ArConfig> {
    if !path.exists() {
        let default = ArConfig::default();
        save_config(path, &default)?;
        info!(config_path = %path.to_string_lossy(), "Created default configuration file");
        return Ok(default);
    }

    let content = fs::read_to_string(path)?;
    let cfg = match toml::from_str(&content) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(
                config_path = %path.to_string_lossy(),
                error = %e,
                "Failed to parse configuration file, using defaults"
            );
            ArConfig::default()
        }
    };
    Ok(cfg)
}

fn save_config(path: &Path, cfg: &ArConfig) -> io::Result<()> {
    let toml = toml::to_string_pretty(cfg).unwrap();
    debug!(config_path = %path.to_string_lossy(), "Saving configuration file");
    fs::write(path, toml)
}

fn enforce_mode_exclusivity(cfg: &mut ArConfig) -> bool {
    if cfg.runtime.spoof_on_file_run
        && (cfg.runtime.run_in_background || cfg.runtime.run_on_startup)
    {
        println!("SPOOF_ON_FILE_RUN cannot be combined with background/startup modes.");
        warn!(
            "SPOOF_ON_FILE_RUN conflicted with background/startup; prioritizing SPOOF_ON_FILE_RUN and disabling background/startup modes"
        );
        cfg.runtime.run_in_background = false;
        cfg.runtime.run_on_startup = false;
        return true;
    }

    false
}

fn sync_startup_task_if_needed(cfg: &ArConfig) {
    if cfg.runtime.spoof_on_file_run {
        info!("Skipping startup task sync because mode is SPOOF_ON_FILE_RUN");
        return;
    }

    let enable_startup = cfg.runtime.run_in_background || cfg.runtime.run_on_startup;
    info!(
        enable_startup,
        run_in_background = cfg.runtime.run_in_background,
        run_on_startup = cfg.runtime.run_on_startup,
        "Syncing startup scheduled task state"
    );
    ArSyncStartupTask(enable_startup);
}

fn run_setup_questions(cfg: &mut ArConfig) -> io::Result<()> {
    loop {
        let automatic_mode = prompt_yes_no(
            "Use Automatic mode? (runs in background and spoofs automatically after Roblox closes)",
        )?;

        if automatic_mode {
            cfg.runtime.spoof_on_file_run = false;
            cfg.runtime.run_in_background = true;
            cfg.runtime.run_on_startup =
                prompt_yes_no("Start Automatic mode on Windows startup? (recommended)")?;

            let notify =
                prompt_yes_no("Ask for confirmation before spoofing after Roblox closes?")?;
            cfg.runtime.spoof_on_roblox_close = if notify {
                SpoofMode::Notify
            } else {
                SpoofMode::Silent
            };
        } else {
            cfg.runtime.spoof_on_file_run = true;
            cfg.runtime.run_in_background = false;
            cfg.runtime.run_on_startup = false;
            cfg.runtime.spoof_on_roblox_close = SpoofMode::Silent;
        }

        cfg.spoofing.clean_and_reinstall =
            prompt_yes_no("Enable trace cleaning & Roblox reinstallation? (heavily recommended)")?;
        cfg.spoofing.spoof_connected_adapters =
            prompt_yes_no("Spoof currently connected Wi-Fi/Ethernet adapters too? (recommended)")?;

        cfg.bootstrapper.use_bootstrapper = prompt_yes_no("Do you use a Roblox bootstrapper?")?;

        if cfg.bootstrapper.use_bootstrapper {
            cfg.bootstrapper.path =
                prompt_existing_file_path("Enter FULL path to bootstrapper executable")?;

            let raw_flag = prompt_string("Custom CLI flag? (leave empty if none)")?;

            cfg.bootstrapper.custom_cli_flag = if raw_flag.trim().is_empty() {
                String::new()
            } else if raw_flag.starts_with("--") {
                raw_flag
            } else {
                format!("--{}", raw_flag)
            };

            cfg.bootstrapper.override_install = prompt_yes_no(
                "Use your bootstrapper instead of the default Roblox installer when installing/updating?",
            )?;

            cfg.bootstrapper.open_roblox_after_spoof =
                prompt_yes_no("Open Roblox automatically after each spoof cycle?")?;
        } else {
            cfg.bootstrapper.path.clear();
            cfg.bootstrapper.custom_cli_flag.clear();
            cfg.bootstrapper.override_install = false;
            cfg.bootstrapper.open_roblox_after_spoof = true;
        }

        print_config_summary(cfg);
        if prompt_yes_no("Does this config look correct?")? {
            break;
        }

        println!("Okay, let's run setup again.\n");
    }

    Ok(())
}

fn prompt_existing_file_path(question: &str) -> io::Result<String> {
    loop {
        let path = prompt_string(question)?;
        if path.is_empty() {
            println!("Path cannot be empty.");
            continue;
        }

        if Path::new(&path).is_file() {
            return Ok(path);
        }

        println!("File not found. Please enter a valid full file path.");
    }
}

fn print_config_summary(cfg: &ArConfig) {
    println!("\n[=== CONFIG SUMMARY ===]");

    if cfg.runtime.run_in_background {
        println!("Mode: Automatic (background monitoring)");
        println!(
            "Start on Windows startup: {}",
            yes_no(cfg.runtime.run_on_startup)
        );
        let close_mode = match cfg.runtime.spoof_on_roblox_close {
            SpoofMode::Notify => "Ask before spoofing",
            SpoofMode::Silent => "Spoof silently",
        };
        println!("On Roblox close: {}", close_mode);
    } else {
        println!("Mode: Manual (spoof when this file is run)");
    }
    println!(
        "clean_and_reinstall: {}",
        yes_no(cfg.spoofing.clean_and_reinstall)
    );
    println!(
        "spoof_connected_adapters: {}",
        yes_no(cfg.spoofing.spoof_connected_adapters)
    );

    println!(
        "Using bootstrapper: {}",
        yes_no(cfg.bootstrapper.use_bootstrapper)
    );
    if cfg.bootstrapper.use_bootstrapper {
        println!("Bootstrapper path: {}", cfg.bootstrapper.path);
        println!(
            "Custom CLI flag: {}",
            if cfg.bootstrapper.custom_cli_flag.is_empty() {
                "(none)"
            } else {
                cfg.bootstrapper.custom_cli_flag.as_str()
            }
        );
        println!(
            "Prefer bootstrapper for installs/updates: {}",
            yes_no(cfg.bootstrapper.override_install)
        );
        println!(
            "Open Roblox after spoof: {}",
            yes_no(cfg.bootstrapper.open_roblox_after_spoof)
        );
    }

    println!();
}

fn yes_no(v: bool) -> &'static str {
    if v { "Yes" } else { "No" }
}

fn pause_before_exit() -> io::Result<()> {
    print!("Press Enter to close setup...");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(())
}

fn prompt_string(question: &str) -> io::Result<String> {
    print!("{question}: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(input.trim().to_string())
}

fn prompt_yes_no(question: &str) -> io::Result<bool> {
    loop {
        print!("{question}: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer y/n."),
        }
    }
}

fn attach_setup_console() {
    unsafe {
        let _ = AllocConsole();

        let title: Vec<u16> = "TRS Setup Wizard".encode_utf16().chain(Some(0)).collect();

        let _ = SetConsoleTitleW(PCWSTR(title.as_ptr()));
    }
}

fn detach_setup_console() {
    unsafe {
        let _ = FreeConsole();
    }
}
