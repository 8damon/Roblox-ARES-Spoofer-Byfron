<h1 align="center">ARES-RS</h1>
<p align="center"><b>Roblox Spoofer</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?logo=rust&style=for-the-badge" />
  <img src="https://img.shields.io/github/actions/workflow/status/8damon/Roblox-ARES-Spoofer-Byfron/ci.yml?label=CI&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Downloads-4K%2B-green?style=for-the-badge" />
  <a href="https://discord.gg/yUWyvT9JyP">
    <img src="https://img.shields.io/discord/1240608336005828668?label=TITAN%20Softworks&logo=discord&color=5865F2&style=for-the-badge" />
  </a>
</p>

## INTRODUCTION

> **ARES-RS** is a successor to the older C++ version of **TITAN-Spoofer**, RS implements many of the limitations of the C++ version, such as configurability, universal bootstrapper support, auto-updating & proper error handling and logging.

# OVERVIEW

ARES-RS is designed to protect your Main/Alt accounts from Byfron's account detection system's & Roblox's BanAsync component. To use this effectively, a VPN is heavily recomended.

For a much more detailed guide, join the **[Discord](https://hub.titansoftwork.com)** and read the guide provided.

## HOW IT WORKS

The Spoofer modifies HWID's (Hardware-Identifier's) to disrupt Roblox's systems.

More in-depth, the Spoofer adjusts to the way you configure it;

```toml
[runtime]
run_on_startup = true # uses scheduled-task
run_in_background = true # required for auto-spoofing
spoof_on_file_run = false # cannot be true when ``run_in_background`` is true
spoof_on_roblox_close = "silent" # OR ``notify``, notify will send a desktop notification

[spoofing]
clean_and_reinstall = true # remove roblox files & reinstall
spoof_connected_adapters = true # spoof Wi-Fi/Ethernet adapter you're connected to

[bootstrapper]
use_bootstrapper = true # using a bootstrapper?
path = 'C:\Users\Damon\AppData\Local\Bloxstrap\Bloxstrap.exe' # filepath to bootstrapper
custom_cli_flag = "" # if your bootstrapper uses a custom flag (default -player)
override_install = true # bootstrapper should be used to install roblox > web installer
open_roblox_after_spoof = false # after spoofing should open roblox app
```

The spoofer works by tracking when Roblox instances are open, once closed if ``spoof_on_roblox_close`` is ``true``, then it will run an automated spoof & notify depending on if its set to ``notify`` or ``silent``.

If ``spoof_on_roblox_close`` is ``false``, then the spoofer will only run when you run the ``aresrs.exe`` program.

For ``spoof_on_roblox_close`` to work, ``run_in_background`` must be ``true``, same applies to ``run_on_startup``.

---

<details>
<summary><span style="font-size: 1.3em; font-weight: 700;">HWIDs SPOOFED</span></summary>

All of these values have been found checked by Roblox's Anti-Tamper (Hyperion/Byfron)


### WMI (via `src/modules/WMI.rs`)

| Class                       | Property     |
| --------------------------- | ------------ |
| Win32_ComputerSystemProduct | UUID         |
| Win32_PhysicalMemory        | SerialNumber |
| Win32_DiskDrive             | SerialNumber |
| Win32_DiskDrive             | PNPDeviceID  |
| Win32_DiskDrive             | DeviceID     |
| Win32_BIOS                  | SerialNumber |
| Win32_BaseBoard             | SerialNumber |
| Win32_Processor             | ProcessorId  |
| Win32_VideoController       | PNPDeviceID  |

---

### Registry Identifiers (via `src/modules/registry.rs`)

| Path                                                            | Description         |
| --------------------------------------------------------------- | ------------------- |
| HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid                | Machine GUID        |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RegisteredOwner  | Registered owner    |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LastLoggedOnUser | Last logged-on user |
| HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY......*\EDID          | Monitor EDID blobs  |

---

### Network Adapter Identity (via `src/modules/adapters/*`)

| Component      | Action                                             |
| -------------- | -------------------------------------------------- |
| Wired adapters | Sets `NetworkAddress`                              |
| WiFi adapters  | Edits profile XML and applies via `WlanSetProfile` |

---

### Volume Serial Modification

(via `src/modules/registry.rs` – `ArSpoofVolume`)

| Filesystem | Action                                  |
| ---------- | --------------------------------------- |
| NTFS       | Writes new serial to volume boot sector |
| FAT        | Writes new serial to volume boot sector |
| FAT32      | Writes new serial to volume boot sector |

</details>

---

## INSTALLATION

For prebuilt binaries (.exe's) you can find them in the **[ARES Discord](https://hub.titansoftwork.com)**.

*PDB's are provided.*

## GUIDE

Prior note, you should be using Web-Roblox, NOT the app, this will log you out of the app each time it spoofs.

Spoofer works by waiting for you to close Roblox then spoofing *afterwards*, if on automatic mode it will do **nothing** when you start it, it is meant to run in the background till Roblox closes. 

### Automatic Mode
1. Download & unzip
2. Run ``aresrs.exe`` in /WIN_x64_RELEASE as Administrator
3. Go through setup config
4. When setup is done, verify ``aresrs.exe`` is running in *Task Manager*

### Manual Mode
1. Download & unzip
2. Run ``aresrs.exe`` in /WIN_x64_RELEASE as Administrator
3. Go through setup config
4. When setup is done, re-run ``aresrs.exe`` as Administrator to spoof


After setup it is required to either **restart your device** or **go into task-scheduler & run "ARESRS-Startup" manually.**

This build is **stable**, if any bugs occur, the spoofer provides logs at `%LOCALAPPDATA%\TSTS`, which you can filter by modification-date & provide to me.

### COMPILING

I do not reccomend this unless you are a developer or a contributor

You will need the [rust programming language](https://rustup.rs).

Clone the repository;

```
git clone https://github.com/8damon/Roblox-ARES-Spoofer-Byfron.git
```

Enter it;

```
cd \Roblox-ARES-Spoofer-Byfron\
```

Build EXE + DLL;

```
cargo build --release --bin aresrs --lib
```

Find outputs in:

- ``target\x86_64-pc-windows-msvc\release\aresrs.exe``
- ``target\x86_64-pc-windows-msvc\release\ares.dll``

---

## IMPORTANT NOTES

- The Spoofer does NOT unban you from specific games OR on-site bans (Eg; Roblox website bans)

---

### DEVELOPER API / DLL USAGE (C ABI)

For DLL integration docs (exports, structs, callback usage, and call flow), see:

- [`DLL_API.md`](./DLL_API.md)


---

## SUPPORT

The Spoofer provides logs at ``%LOCALAPPDATA%\TSRS``, filter by modified-date & upload the relevant log file to said thread,

Open a support thread via the **[TITAN Discord](https://hub.titansoftwork.com)**.

## CONTRIBUTING

Contributions are welcome (bugfixes, refactors, docs, CI improvements).

### Setup
- Install Rust: https://rustup.rs
- Clone:

```
git clone https://github.com/8damon/Aoblox-ARES-Spoofer-Byfron.git
cd Roblox-ARES-Spoofer-Byfron
```

### Before Opening A PR
- Format:

```
cargo fmt --all
```

- Verify build:

```
cargo check
```

### Guidelines
- Keep changes scoped and explain intent in the PR description.
- Prefer small, reviewable commits.
- Add/extend tracing on non-obvious error paths.
- Avoid introducing user-configurable update/exec sources.

## LICENSE

ARES Spoofer RS is licensed under Apache 2.0 with the Commons Clause.

- You may use, modify, and redistribute the software with attribution.
- You may **not Sell** the software or any service whose value derives substantially from it.
- Commercial use is prohibited unless you obtain explicit written permission from ARES Softwork Solutions.

## LEGAL
This software is provided for **educational and research purposes only**. The use of this tool to **circumvent security protections** or violate the terms of service of **Roblox or any other platform** is strictly prohibited. The developers **do not endorse or condone** any illegal activities and assume no liability for misuse.
