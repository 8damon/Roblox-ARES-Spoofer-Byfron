#[path = "engine/platform.rs"]
mod platform;
#[path = "engine/types.rs"]
mod types;

use crate::components::update::{ArCheckForUpdates, UpdateResult};
use crate::modules::{
    WMI::ArSpoofWMI,
    adapters::{
        ArCaptureActiveNetworkSnapshot, ArLogNetworkPreflight, ArSpoofMAC,
        ArVerifyNetworkPreservedAfterMacSpoof,
    },
    clean::TraceCleaner,
    install::{ArInstall, InstallLaunch},
    post_check::{ArCaptureSpoofState, ArVerifySpoofApplied},
    registry::ArSpoofRegistry,
};

use self::platform::{
    any_roblox_window_visible, kill_roblox_processes, pid_has_roblox_window,
    process_exists_by_names, wait_for_process_to_close,
};
use self::types::{BackgroundState, ExecutionMode, PlayerTrack, ProcessProvenance};
use crate::{
    etw,
    setup::setup::{ArConfig, SpoofMode},
};

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub struct TrsEngine {
    cfg: ArConfig,
    mode: ExecutionMode,
    etw_rx: Option<std::sync::mpsc::Receiver<etw::RobloxAlert>>,
    etw_subsystem: Option<etw::ArEtwSubsystem>,
    background_state: BackgroundState,
    generation: u64,
    saw_user_presence_since_arm: bool,
    armed_user_presence_since: Option<Instant>,
    close_condition_since: Option<Instant>,
    cooldown_until: Option<Instant>,
    installer_fence_until: Option<Instant>,
    active_roblox_pids: HashSet<u32>,
    player_tracks: HashMap<u32, PlayerTrack>,
    cached_any_window: bool,
    last_window_probe: Instant,
    armed_last_user_present: bool,
    installer_spawn_pid: Option<u32>,
}

impl TrsEngine {
    const MIN_SESSION_BEFORE_CLOSE_TRIGGER: Duration = Duration::from_secs(20);
    const MIN_CLOSE_STABLE_WINDOW: Duration = Duration::from_secs(3);
    const POST_SPOOF_COOLDOWN: Duration = Duration::from_secs(25);
    const INSTALLER_FENCE_DURATION: Duration = Duration::from_secs(45);
    const BG_RECV_TIMEOUT: Duration = Duration::from_secs(2);
    const WINDOW_PROBE_INTERVAL: Duration = Duration::from_secs(3);
    const NETWORK_VERIFY_WAIT: Duration = Duration::from_secs(12);
    const WAIT_REARM_INSTALLER_SECS: Duration = Duration::from_secs(30);
    const WAIT_REARM_NORMAL_SECS: Duration = Duration::from_secs(15);

    pub fn new(cfg: ArConfig) -> Self {
        let mode = Self::resolve_mode(&cfg);
        let now = Instant::now();

        Self {
            cfg,
            mode,
            etw_rx: None,
            etw_subsystem: None,
            background_state: BackgroundState::Armed,
            generation: 0,
            saw_user_presence_since_arm: false,
            armed_user_presence_since: None,
            close_condition_since: None,
            cooldown_until: None,
            installer_fence_until: None,
            active_roblox_pids: HashSet::new(),
            player_tracks: HashMap::new(),
            cached_any_window: false,
            last_window_probe: now - Self::WINDOW_PROBE_INTERVAL,
            armed_last_user_present: false,
            installer_spawn_pid: None,
        }
    }

    pub fn run(mut self) -> anyhow::Result<()> {
        info!("TRS Engine starting");
        info!(
            run_in_background = self.cfg.runtime.run_in_background,
            run_on_startup = self.cfg.runtime.run_on_startup,
            spoof_on_file_run = self.cfg.runtime.spoof_on_file_run,
            spoof_on_roblox_close = match self.cfg.runtime.spoof_on_roblox_close {
                SpoofMode::Silent => "silent",
                SpoofMode::Notify => "notify",
            },
            "Runtime config snapshot"
        );

        if matches!(self.mode, ExecutionMode::OneShot) {
            info!("Mode: OneShot");
            self.execute_full_cycle();
            return Ok(());
        }

        self.init_etw();

        if self.update_check() {
            return Ok(());
        }
        let _ = ArLogNetworkPreflight();
        let startup_boot = self.should_run_on_startup();
        if startup_boot {
            self.execute_startup_hwid_cycle();
        }

        match self.mode {
            ExecutionMode::OneShot => unreachable!("OneShot mode exits before background dispatch"),
            ExecutionMode::BackgroundSilent | ExecutionMode::BackgroundNotify => {
                if self.etw_rx.is_none() {
                    warn!(
                        "Background mode requested but ETW failed to initialize. Falling back to Normal mode."
                    );
                    self.execute_full_cycle();
                    return Ok(());
                }

                let notify = matches!(self.mode, ExecutionMode::BackgroundNotify);
                info!(
                    "Mode: {}",
                    if notify {
                        "BackgroundNotify"
                    } else {
                        "BackgroundSilent"
                    }
                );
                self.background_loop(notify);
            }

            ExecutionMode::Normal => {
                info!("Mode: Normal");
                if startup_boot {
                    info!("Startup boot detected in Normal mode; skipped clean/reinstall");
                } else {
                    self.execute_full_cycle();
                }
            }
        }

        Ok(())
    }

    //
    // CORE PIPELINE
    //

    fn execute_full_cycle(&mut self) {
        self.generation = self.generation.saturating_add(1);
        info!(generation = self.generation, "Started new spoof generation");

        if self.cfg.spoofing.clean_and_reinstall {
            self.run_trace_cleaner();
        } else {
            info!("CLEAN_AND_REINSTALL=false: skipping trace cleaner");
        }
        self.run_spoof_pipeline();
        if self.cfg.spoofing.clean_and_reinstall {
            self.install();
        } else {
            info!("CLEAN_AND_REINSTALL=false: skipping reinstall");
        }

        let now = Instant::now();
        self.cooldown_until = Some(now + Self::POST_SPOOF_COOLDOWN);
        self.installer_fence_until = Some(now + Self::INSTALLER_FENCE_DURATION);
        self.installer_spawn_pid = None;
    }

    fn execute_startup_hwid_cycle(&mut self) {
        self.generation = self.generation.saturating_add(1);
        info!(
            generation = self.generation,
            "Startup boot detected: running HWID-only spoof cycle (no cleaner/reinstall)"
        );
        self.run_spoof_pipeline();
    }

    //
    // Internal helpers
    //

    fn init_etw(&mut self) {
        match etw::ArStartETWSubsystem() {
            Ok((subsystem, rx)) => {
                self.etw_rx = Some(rx);
                self.etw_subsystem = Some(subsystem);
            }
            Err(e) => warn!("ETW subsystem failed: {e}"),
        }
    }

    fn update_check(&self) -> bool {
        match ArCheckForUpdates(&self.cfg) {
            Ok(UpdateResult::UpdateStaged) => {
                info!("Update staged, exiting");
                true
            }
            Ok(_) => false,
            Err(e) => {
                warn!("Update check error: {e}");
                false
            }
        }
    }

    fn run_trace_cleaner(&self) {
        let bootstrapper_enabled = self.cfg.bootstrapper.use_bootstrapper;

        let bootstrapper_name = if bootstrapper_enabled {
            Some(self.cfg.bootstrapper.path.as_str())
        } else {
            None
        };

        info!("Running trace cleaner");
        TraceCleaner::run(bootstrapper_enabled, bootstrapper_name);
    }

    fn run_spoof_pipeline(&self) {
        info!("Running spoof pipeline");
        let pre_state = ArCaptureSpoofState();

        ArSpoofWMI();
        ArSpoofRegistry();
        let pre_mac_network = ArCaptureActiveNetworkSnapshot();
        ArSpoofMAC(self.cfg.spoofing.spoof_connected_adapters);
        if let Some(pre) = pre_mac_network.as_ref() {
            let _ = ArVerifyNetworkPreservedAfterMacSpoof(pre, Self::NETWORK_VERIFY_WAIT);
        }
        let report = ArVerifySpoofApplied(&pre_state);
        info!(
            machine_guid_changed = report.machine_guid_changed,
            mac_values_changed = report.mac_values_changed,
            mac_values_total = report.mac_values_total,
            passed = report.passed(),
            "Post-spoof verification report"
        );

        info!("Spoof pipeline complete");
    }

    fn install(&mut self) {
        info!("Running installer");
        self.installer_spawn_pid = None;

        match ArInstall(&self.cfg) {
            InstallLaunch::Bootstrapper => {
                if !self.cfg.bootstrapper.open_roblox_after_spoof {
                    info!("Bootstrapper post-spoof Roblox launch suppression started");
                    suppress_bootstrapper_opened_roblox_once();
                }
            }
            InstallLaunch::RobloxInstaller => {
                wait_for_process_to_close("RobloxPlayerInstaller.exe", Duration::from_secs(900));
                kill_roblox_processes();
            }
            InstallLaunch::None => {}
        }
    }

    fn background_loop(&mut self, notify: bool) {
        let Some(rx) = self.etw_rx.take() else {
            warn!("ETW not initialized; background loop aborted.");
            return;
        };

        loop {
            let timeout = Self::BG_RECV_TIMEOUT;

            match rx.recv_timeout(timeout) {
                Ok(etw::RobloxAlert::ProcessStart { instance }) => {
                    if instance.exe == etw::RobloxExe::RobloxPlayerBeta {
                        let now = Instant::now();
                        let in_installer_fence = self
                            .installer_fence_until
                            .map(|until| now < until)
                            .unwrap_or(false);
                        let provenance = if in_installer_fence {
                            ProcessProvenance::InstallerSpawned
                        } else {
                            ProcessProvenance::UserSpawned
                        };

                        self.active_roblox_pids.insert(instance.pid);
                        self.player_tracks.insert(
                            instance.pid,
                            PlayerTrack {
                                started: now,
                                generation: self.generation,
                                saw_window: false,
                                provenance,
                            },
                        );

                        if provenance == ProcessProvenance::InstallerSpawned
                            && self.installer_spawn_pid.is_none()
                        {
                            self.installer_spawn_pid = Some(instance.pid);
                            info!(
                                generation = self.generation,
                                pid = instance.pid,
                                "Tagged Roblox process as installer-launched"
                            );
                        }
                    }
                }
                Ok(etw::RobloxAlert::ProcessStop { instance }) => {
                    if instance.exe != etw::RobloxExe::RobloxPlayerBeta {
                        continue;
                    }
                    self.active_roblox_pids.remove(&instance.pid);
                    self.player_tracks.remove(&instance.pid);
                    if self.installer_spawn_pid == Some(instance.pid) {
                        self.installer_spawn_pid = None;
                    }
                }
                Ok(_) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }

            self.update_window_observations();

            self.tick_background_state(notify);
        }

        self.etw_rx = Some(rx);
    }

    fn tick_background_state(&mut self, notify: bool) {
        let now = Instant::now();
        let any_process = !self.active_roblox_pids.is_empty();
        let any_window = self.current_any_window(any_process, now);
        let cooldown_active = self
            .cooldown_until
            .map(|until| now < until)
            .unwrap_or(false);
        let installer_fence_active = self
            .installer_fence_until
            .map(|until| now < until)
            .unwrap_or(false);

        let any_user_open = self.player_tracks.iter().any(|(pid, track)| {
            self.active_roblox_pids.contains(pid)
                && track.generation == self.generation
                && track.provenance == ProcessProvenance::UserSpawned
        });
        let close_condition = !any_process || !any_window;

        match &mut self.background_state {
            BackgroundState::Armed => {
                if any_user_open {
                    if !self.saw_user_presence_since_arm {
                        self.armed_user_presence_since = Some(now);
                    }
                    self.saw_user_presence_since_arm = true;
                    self.armed_last_user_present = true;
                    self.close_condition_since = None;
                    return;
                }

                if !close_condition {
                    self.close_condition_since = None;
                    return;
                }

                if !self.saw_user_presence_since_arm {
                    self.close_condition_since = None;
                    self.armed_last_user_present = false;
                    return;
                }

                if !self.armed_last_user_present {
                    self.close_condition_since = None;
                    return;
                }

                let Some(seen_at) = self.armed_user_presence_since else {
                    self.close_condition_since = None;
                    return;
                };
                if now.duration_since(seen_at) < Self::MIN_SESSION_BEFORE_CLOSE_TRIGGER {
                    self.close_condition_since = None;
                    return;
                }
                if cooldown_active {
                    return;
                }

                match self.close_condition_since {
                    Some(since) if now.duration_since(since) >= Self::MIN_CLOSE_STABLE_WINDOW => {}
                    Some(_) => return,
                    None => {
                        self.close_condition_since = Some(now);
                        return;
                    }
                }

                if notify && !crate::components::notify::ask_user_to_spoof() {
                    self.reset_session_tracking();
                    return;
                }

                self.execute_full_cycle();
                self.transition_background_state(
                    BackgroundState::IgnoreNextClose {
                        session_seen: false,
                    },
                    "spoof_cycle_completed",
                );
                self.reset_session_tracking();
            }

            BackgroundState::IgnoreNextClose { session_seen } => {
                if any_process {
                    *session_seen = true;
                }

                if *session_seen && !any_process {
                    info!(
                        generation = self.generation,
                        "Ignored first post-spoof Roblox close"
                    );
                    if !self.cfg.bootstrapper.open_roblox_after_spoof {
                        self.clear_post_install_gates("installer_spawn_suppressed_and_closed");
                    }
                    self.transition_background_state(
                        BackgroundState::WaitForRealPlay,
                        "ignored_first_post_spoof_close",
                    );
                    self.reset_session_tracking();
                }

                if let Some(pid) = self.installer_spawn_pid
                    && any_process
                    && self.active_roblox_pids.contains(&pid)
                {
                    let track = self.player_tracks.get(&pid);
                    let saw_window = track.map(|t| t.saw_window).unwrap_or(false);
                    let installer_elapsed = track
                        .map(|t| now.duration_since(t.started))
                        .unwrap_or_default();
                    if self.cfg.bootstrapper.open_roblox_after_spoof
                        && installer_elapsed >= Self::WAIT_REARM_INSTALLER_SECS
                        && saw_window
                        && !cooldown_active
                    {
                        info!(
                            generation = self.generation,
                            pid,
                            installer_elapsed_secs = installer_elapsed.as_secs(),
                            saw_window,
                            "Re-arming from installer-launched Roblox long-run gate"
                        );
                        self.transition_background_state(
                            BackgroundState::Armed,
                            "installer_spawn_survived_gate",
                        );
                        self.saw_user_presence_since_arm = true;
                        self.armed_user_presence_since = Some(
                            now.checked_sub(Self::MIN_SESSION_BEFORE_CLOSE_TRIGGER)
                                .unwrap_or(now),
                        );
                        self.armed_last_user_present = true;
                        self.close_condition_since = None;
                        self.installer_spawn_pid = None;
                    }
                }
            }

            BackgroundState::WaitForRealPlay => {
                let qualifying_user = self
                    .player_tracks
                    .iter()
                    .filter(|(pid, track)| {
                        self.active_roblox_pids.contains(pid)
                            && track.generation == self.generation
                            && track.provenance == ProcessProvenance::UserSpawned
                            && track.saw_window
                            && now.duration_since(track.started) >= Self::WAIT_REARM_NORMAL_SECS
                    })
                    .count()
                    > 0;
                info!(
                    generation = self.generation,
                    qualifying_user,
                    threshold_secs = Self::WAIT_REARM_NORMAL_SECS.as_secs(),
                    active_instances = self.active_roblox_pids.len(),
                    installer_fence_active,
                    cooldown_active,
                    "WaitForRealPlay classifier conditions"
                );

                if !installer_fence_active && !cooldown_active && qualifying_user {
                    info!(
                        generation = self.generation,
                        "Background close trigger re-armed from user time gate"
                    );
                    self.transition_background_state(BackgroundState::Armed, "user_time_gate_met");
                    self.saw_user_presence_since_arm = true;
                    self.armed_user_presence_since = Some(
                        now.checked_sub(Self::MIN_SESSION_BEFORE_CLOSE_TRIGGER)
                            .unwrap_or(now),
                    );
                    self.armed_last_user_present = true;
                    self.close_condition_since = None;
                }
            }
        }
    }

    fn reset_session_tracking(&mut self) {
        self.saw_user_presence_since_arm = false;
        self.armed_user_presence_since = None;
        self.armed_last_user_present = false;
        self.close_condition_since = None;
    }

    fn current_any_window(&mut self, any_process: bool, now: Instant) -> bool {
        if !any_process {
            self.cached_any_window = false;
            return false;
        }

        if now.duration_since(self.last_window_probe) >= Self::WINDOW_PROBE_INTERVAL {
            self.cached_any_window = any_roblox_window_visible();
            self.last_window_probe = now;
        }

        self.cached_any_window
    }

    fn update_window_observations(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_window_probe) < Self::WINDOW_PROBE_INTERVAL {
            return;
        }
        self.last_window_probe = now;

        let pids: Vec<u32> = self
            .player_tracks
            .iter()
            .filter_map(|(pid, track)| (!track.saw_window).then_some(*pid))
            .collect();
        for pid in pids {
            if self.active_roblox_pids.contains(&pid)
                && pid_has_roblox_window(pid)
                && let Some(track) = self.player_tracks.get_mut(&pid)
            {
                track.saw_window = true;
            }
        }
    }

    fn transition_background_state(&mut self, new_state: BackgroundState, reason: &'static str) {
        info!(
            generation = self.generation,
            from = Self::background_state_name(&self.background_state),
            to = Self::background_state_name(&new_state),
            reason,
            "Background state transition"
        );
        self.background_state = new_state;
    }

    fn background_state_name(state: &BackgroundState) -> &'static str {
        match state {
            BackgroundState::Armed => "Armed",
            BackgroundState::IgnoreNextClose { .. } => "IgnoreNextClose",
            BackgroundState::WaitForRealPlay => "WaitForRealPlay",
        }
    }

    fn clear_post_install_gates(&mut self, reason: &'static str) {
        self.installer_fence_until = None;
        self.cooldown_until = None;
        self.installer_spawn_pid = None;
        info!(
            generation = self.generation,
            reason, "Cleared post-install gate"
        );
    }

    fn should_run_on_startup(&self) -> bool {
        if !self.cfg.runtime.run_on_startup {
            return false;
        }

        use windows::Win32::System::SystemInformation::GetTickCount64;

        let uptime_ms = unsafe { GetTickCount64() };

        uptime_ms < 120_000
    }

    fn resolve_mode(cfg: &ArConfig) -> ExecutionMode {
        if cfg.runtime.spoof_on_file_run {
            return ExecutionMode::OneShot;
        }

        if cfg.runtime.run_in_background {
            match cfg.runtime.spoof_on_roblox_close {
                SpoofMode::Notify => ExecutionMode::BackgroundNotify,
                SpoofMode::Silent => ExecutionMode::BackgroundSilent,
            }
        } else {
            ExecutionMode::Normal
        }
    }
}

fn suppress_bootstrapper_opened_roblox_once() {
    let max_wait = Duration::from_secs(90);
    let poll = Duration::from_millis(150);
    let start = Instant::now();
    let mut seen_open_at: Option<Instant> = None;

    while start.elapsed() < max_wait {
        let opened = process_exists_by_names(&["RobloxPlayerBeta.exe", "RobloxPlayerLauncher.exe"]);

        if opened && seen_open_at.is_none() {
            seen_open_at = Some(Instant::now());
            info!("Detected bootstrapper-opened Roblox; suppression timer started");
        }

        if let Some(opened_at) = seen_open_at {
            if any_roblox_window_visible() {
                info!("Suppressing bootstrapper-opened Roblox on first window");
                kill_roblox_processes();
                return;
            }

            if opened_at.elapsed() >= Duration::from_secs(3) {
                info!("Suppressing bootstrapper-opened Roblox after 3s grace period");
                kill_roblox_processes();
                return;
            }
        }

        std::thread::sleep(poll);
    }
}
