use sha2::Digest;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_DWORD,
    REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
};
use windows::Win32::UI::Shell::{
    QUNS_ACCEPTS_NOTIFICATIONS, QUNS_APP, QUNS_BUSY, QUNS_NOT_PRESENT, QUNS_PRESENTATION_MODE,
    QUNS_QUIET_TIME, QUNS_RUNNING_D3D_FULL_SCREEN, SHQueryUserNotificationState,
};
use windows::core::PCWSTR;

#[cfg(target_arch = "x86")]
use std::arch::x86::__cpuid;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__cpuid;

#[derive(Clone)]
struct FileMakeWriter {
    file: Arc<Mutex<File>>,
}

#[derive(Clone, Copy)]
struct ConsoleMakeWriter {
    strip_ansi: bool,
}

struct FileWriter {
    file: Arc<Mutex<File>>,
}

struct ConsoleWriter {
    strip_ansi: bool,
}

static MUTE_CONSOLE_TRACING: AtomicBool = AtomicBool::new(false);
static CONSOLE_ANSI_TRACING: AtomicBool = AtomicBool::new(true);

pub fn ArSetConsoleTracingMuted(muted: bool) {
    MUTE_CONSOLE_TRACING.store(muted, Ordering::Relaxed);
}

pub fn ArSetConsoleTracingAnsi(enabled: bool) {
    CONSOLE_ANSI_TRACING.store(enabled, Ordering::Relaxed);
}

impl<'a> MakeWriter<'a> for FileMakeWriter {
    type Writer = FileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        FileWriter {
            file: self.file.clone(),
        }
    }
}

impl Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Ok(mut file) = self.file.lock() {
            file.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Ok(mut file) = self.file.lock() {
            file.flush()?;
        }
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for ConsoleMakeWriter {
    type Writer = ConsoleWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ConsoleWriter {
            strip_ansi: self.strip_ansi,
        }
    }
}

impl Write for ConsoleWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut stdout = io::stdout();
        if self.strip_ansi {
            let stripped = strip_ansi_escape_sequences(buf);
            stdout.write_all(&stripped)?;
        } else {
            stdout.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

fn strip_ansi_escape_sequences(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;

    while i < input.len() {
        if input[i] == 0x1B && i + 1 < input.len() && input[i + 1] == b'[' {
            i += 2;
            while i < input.len() {
                let b = input[i];
                i += 1;
                if (0x40..=0x7E).contains(&b) {
                    break;
                }
            }
            continue;
        }

        out.push(input[i]);
        i += 1;
    }

    out
}

fn init_log_file() -> Option<Arc<Mutex<File>>> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);

    let dir = base.join("TSRS");
    if fs::create_dir_all(&dir).is_err() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let name = format!("tsrs_{}_{}.log", ts, std::process::id());
    let path = dir.join(name);

    let file = File::options().create(true).append(true).open(path).ok()?;

    Some(Arc::new(Mutex::new(file)))
}

pub fn ArTracing() {
    let default_filter = if cfg!(debug_assertions) {
        "aresrs=debug,tsrs=debug,ureq=warn,ureq_proto=warn,native_tls=warn,rustls=warn"
    } else {
        "aresrs=info,tsrs=info,ureq=warn,ureq_proto=warn,native_tls=warn,rustls=warn"
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    let timer = ChronoLocal::new("%Y-%m-%d %H:%M:%S".to_string());
    let no_console = MUTE_CONSOLE_TRACING.load(Ordering::Relaxed);
    let console_ansi = CONSOLE_ANSI_TRACING.load(Ordering::Relaxed);

    if let Some(file) = init_log_file() {
        if no_console {
            let file_layer = fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_file(false)
                .with_line_number(false)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_level(true)
                .with_timer(timer)
                .with_writer(FileMakeWriter { file });

            tracing_subscriber::registry()
                .with(filter)
                .with(file_layer)
                .init();
        } else {
            let stdout_layer = fmt::layer()
                .with_ansi(console_ansi)
                .with_target(true)
                .with_file(true)
                .with_line_number(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_level(true)
                .with_timer(timer.clone())
                .with_writer(ConsoleMakeWriter {
                    strip_ansi: !console_ansi,
                });
            let file_layer = fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_file(false)
                .with_line_number(false)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_level(true)
                .with_timer(timer)
                .with_writer(FileMakeWriter { file });

            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .init();
        }
    } else if no_console {
        tracing_subscriber::registry().with(filter).init();
    } else {
        let stdout_layer = fmt::layer()
            .with_ansi(console_ansi)
            .with_target(true)
            .with_file(true)
            .with_line_number(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_level(true)
            .with_timer(timer)
            .with_writer(ConsoleMakeWriter {
                strip_ansi: !console_ansi,
            });

        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .init();
    }

    ArLogStartupDiagnostics();
}

#[repr(C)]
struct RTL_OSVERSIONINFOW {
    dwOSVersionInfoSize: u32,
    dwMajorVersion: u32,
    dwMinorVersion: u32,
    dwBuildNumber: u32,
    dwPlatformId: u32,
    szCSDVersion: [u16; 128],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(lpVersionInformation: *mut RTL_OSVERSIONINFOW) -> i32;
}

fn ArLogStartupDiagnostics() {
    let (major, minor, build) = query_windows_version().unwrap_or((0, 0, 0));
    let os_family = if build >= 22_000 {
        "Windows 11"
    } else {
        "Windows 10/legacy"
    };

    let cpu_vendor = query_cpu_vendor();
    let cpu_class = if cpu_vendor.contains("AuthenticAMD") {
        "AMD"
    } else if cpu_vendor.contains("GenuineIntel") {
        "Intel"
    } else {
        "Unknown"
    };

    let security_intelligence = read_reg_string(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates",
        "AVSignatureVersion",
    )
    .unwrap_or_else(|| "unknown".to_string());

    let dnd_status = query_do_not_disturb_status();

    let sha256 =
        compute_current_process_sha256_with_timeout().unwrap_or_else(|| "unavailable".to_string());

    info!(
        os_major = major,
        os_minor = minor,
        os_build = build,
        os_family,
        security_intelligence = %security_intelligence,
        do_not_disturb = dnd_status,
        cpu_vendor = %cpu_vendor,
        cpu_class,
        process_sha256 = %sha256,
        "Startup diagnostics preflight"
    );
}

fn query_do_not_disturb_status() -> &'static str {
    if let Ok(state) = unsafe { SHQueryUserNotificationState() } {
        return match state {
            QUNS_ACCEPTS_NOTIFICATIONS => "disabled",
            QUNS_BUSY
            | QUNS_RUNNING_D3D_FULL_SCREEN
            | QUNS_PRESENTATION_MODE
            | QUNS_QUIET_TIME
            | QUNS_APP => "enabled",
            QUNS_NOT_PRESENT => "unknown",
            _ => "unknown",
        };
    }

    // Registry fallback (older systems / API failure cases)
    match read_reg_dword(
        HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings",
        "NOC_GLOBAL_SETTING_TOASTS_ENABLED",
    ) {
        Some(0) => "enabled",
        Some(_) => "disabled",
        None => "unknown",
    }
}

fn query_windows_version() -> Option<(u32, u32, u32)> {
    let mut info = RTL_OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<RTL_OSVERSIONINFOW>() as u32,
        dwMajorVersion: 0,
        dwMinorVersion: 0,
        dwBuildNumber: 0,
        dwPlatformId: 0,
        szCSDVersion: [0u16; 128],
    };

    let status = unsafe { RtlGetVersion(&mut info as *mut RTL_OSVERSIONINFOW) };
    if status == 0 {
        Some((info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber))
    } else {
        None
    }
}

fn query_cpu_vendor() -> String {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        let leaf = unsafe { __cpuid(0) };
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&leaf.ebx.to_le_bytes());
        bytes.extend_from_slice(&leaf.edx.to_le_bytes());
        bytes.extend_from_slice(&leaf.ecx.to_le_bytes());
        String::from_utf8(bytes).unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        "unknown".to_string()
    }
}

fn compute_current_process_sha256_with_timeout() -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(compute_current_process_sha256());
    });
    match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(value) => value,
        Err(_) => Some("timeout".to_string()),
    }
}

fn compute_current_process_sha256() -> Option<String> {
    let path = std::env::current_exe().ok()?;
    let mut file = File::open(path).ok()?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let read = file.read(&mut buf).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }

    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    Some(out)
}

fn read_reg_string(root: HKEY, key_path: &str, value_name: &str) -> Option<String> {
    let mut h_key = HKEY::default();
    let key_w: Vec<u16> = key_path.encode_utf16().chain(Some(0)).collect();
    let value_w: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();

    if unsafe {
        RegOpenKeyExW(
            root,
            PCWSTR(key_w.as_ptr()),
            None,
            KEY_READ | KEY_WOW64_64KEY,
            &mut h_key,
        )
    } != ERROR_SUCCESS
    {
        return None;
    }

    let mut value_type = REG_VALUE_TYPE(0);
    let mut byte_len = 0u32;
    let len_rc = unsafe {
        RegQueryValueExW(
            h_key,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut value_type),
            None,
            Some(&mut byte_len),
        )
    };
    if len_rc != ERROR_SUCCESS
        || byte_len == 0
        || !(value_type == REG_SZ || value_type == REG_EXPAND_SZ)
    {
        unsafe {
            let _ = RegCloseKey(h_key);
        }
        return None;
    }

    let mut buf = vec![0u8; byte_len as usize];
    let val_rc = unsafe {
        RegQueryValueExW(
            h_key,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut value_type),
            Some(buf.as_mut_ptr()),
            Some(&mut byte_len),
        )
    };
    unsafe {
        let _ = RegCloseKey(h_key);
    }
    if val_rc != ERROR_SUCCESS || byte_len < 2 {
        return None;
    }

    let u16_len = (byte_len as usize) / 2;
    let wide = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u16, u16_len) };
    let nul = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    let value = String::from_utf16_lossy(&wide[..nul]).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn read_reg_dword(root: HKEY, key_path: &str, value_name: &str) -> Option<u32> {
    let mut h_key = HKEY::default();
    let key_w: Vec<u16> = key_path.encode_utf16().chain(Some(0)).collect();
    let value_w: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();

    if unsafe {
        RegOpenKeyExW(
            root,
            PCWSTR(key_w.as_ptr()),
            None,
            KEY_READ | KEY_WOW64_64KEY,
            &mut h_key,
        )
    } != ERROR_SUCCESS
    {
        return None;
    }

    let mut value_type = REG_VALUE_TYPE(0);
    let mut data = 0u32;
    let mut data_len = std::mem::size_of::<u32>() as u32;
    let rc = unsafe {
        RegQueryValueExW(
            h_key,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut value_type),
            Some((&mut data as *mut u32).cast::<u8>()),
            Some(&mut data_len),
        )
    };
    unsafe {
        let _ = RegCloseKey(h_key);
    }

    if rc == ERROR_SUCCESS && value_type == REG_DWORD {
        Some(data)
    } else {
        None
    }
}
