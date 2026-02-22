use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::setup::setup::ArConfig;

const TRUSTED_REPO_GIT: &str = "8damon/Roblox-ARES-Spoofer-Byfron.git";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateResult {
    Skipped,
    UpToDate,
    UpdateStaged,
}

pub fn ArCheckForUpdates(cfg: &ArConfig) -> io::Result<UpdateResult> {
    if !cfg.update.enabled {
        return Ok(UpdateResult::Skipped);
    }

    let latest = match github_latest_release() {
        Ok(v) => v,
        Err(_) => return Ok(UpdateResult::Skipped),
    };

    let current = parse_version3(env!("CARGO_PKG_VERSION")).unwrap_or(Version3(0, 0, 0));

    let latest_ver = match parse_version3(&latest.tag_name) {
        Some(v) => v,
        None => return Ok(UpdateResult::Skipped),
    };

    if latest_ver <= current {
        return Ok(UpdateResult::UpToDate);
    }

    if !cfg.update.auto_install {
        return Ok(UpdateResult::Skipped);
    }

    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| io::Error::other("Executable has no parent directory"))?;

    let Some(asset) = latest
        .assets
        .iter()
        .find(|a| a.name.to_ascii_lowercase().ends_with(".exe"))
    else {
        return Ok(UpdateResult::Skipped);
    };

    let staged_path = staged_exe_path(&exe_path);
    download_to_file(&asset.browser_download_url, &staged_path)?;

    let cmd_path = exe_dir.join("titan_update.cmd");
    write_update_cmd(&cmd_path, &exe_path, &staged_path)?;
    launch_update_cmd(&cmd_path)?;

    Ok(UpdateResult::UpdateStaged)
}

//
// Version parsing
//

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Version3(u64, u64, u64);

impl fmt::Display for Version3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

fn parse_version3(s: &str) -> Option<Version3> {
    let s = s.trim().strip_prefix('v').unwrap_or(s);
    let s = s.split_once('-').map(|(a, _)| a).unwrap_or(s);

    let mut it = s.split('.');
    Some(Version3(
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ))
}

//
// GitHub API
//

#[derive(Debug)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

fn github_latest_release() -> Result<GithubRelease, io::Error> {
    let repo_path = TRUSTED_REPO_GIT
        .strip_suffix(".git")
        .unwrap_or(TRUSTED_REPO_GIT);
    let url = format!("https://api.github.com/repos/{repo_path}/releases/latest");

    let resp = ureq::get(&url)
        .header("User-Agent", "titan-rs-updater")
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| io::Error::other(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(io::Error::other(format!(
            "GitHub returned {}",
            resp.status()
        )));
    }

    let body = resp
        .into_body()
        .read_to_string()
        .map_err(|e| io::Error::other(e.to_string()))?;

    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| io::Error::other(e.to_string()))?;

    let tag_name = v["tag_name"]
        .as_str()
        .ok_or_else(|| io::Error::other("missing tag_name"))?
        .to_string();

    let assets = v["assets"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|a| {
            Some(GithubAsset {
                name: a["name"].as_str()?.to_string(),
                browser_download_url: a["browser_download_url"].as_str()?.to_string(),
            })
        })
        .collect();

    Ok(GithubRelease { tag_name, assets })
}

//
// File helpers
//

fn staged_exe_path(current_exe: &Path) -> PathBuf {
    let dir = current_exe.parent().unwrap_or_else(|| Path::new("."));
    let stem = current_exe
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("titan");

    dir.join(format!("{stem}.new.exe"))
}

fn download_to_file(url: &str, path: &Path) -> io::Result<()> {
    let resp = ureq::get(url)
        .header("User-Agent", "titan-rs-updater")
        .call()
        .map_err(|e| io::Error::other(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(io::Error::other(format!(
            "Download failed: HTTP {}",
            resp.status()
        )));
    }

    let mut reader = resp.into_body().into_reader();
    let mut file = fs::File::create(path)?;
    io::copy(&mut reader, &mut file)?;

    Ok(())
}

fn write_update_cmd(cmd_path: &Path, exe_path: &Path, new_exe_path: &Path) -> io::Result<()> {
    let pid = std::process::id();
    let exe_s = exe_path.to_string_lossy();
    let new_s = new_exe_path.to_string_lossy();
    let old_s = format!("{exe_s}.old");

    let script = format!(
        "@echo off\r\n\
powershell -NoProfile -Command \"try {{ Wait-Process -Id {pid} }} catch {{ }}\"\r\n\
move /y \"{exe_s}\" \"{old_s}\" >nul 2>nul\r\n\
move /y \"{new_s}\" \"{exe_s}\" >nul 2>nul\r\n\
start \"\" \"{exe_s}\"\r\n"
    );

    fs::write(cmd_path, script)
}

fn launch_update_cmd(cmd_path: &Path) -> io::Result<()> {
    Command::new("cmd")
        .args(["/C", "start", "", cmd_path.to_string_lossy().as_ref()])
        .spawn()
        .map(|_| ())
        .map_err(|e| io::Error::other(e.to_string()))
}
