#![allow(dead_code)]

use std::time::{Duration, Instant};

use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WiFi::*;
use windows::core::{GUID, PCWSTR, PWSTR};

use tracing::{debug, error, info, warn};

use super::profile_xml::ensure_mac_randomization;
use super::util::wide_null;

const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn spoof_connected_wifi_interfaces() {
    info!("Starting WiFi spoof routine");

    let force_reconnect = env_flag("TSRS_WIFI_FORCE_RECONNECT", false);

    let mut version = 0u32;
    let mut handle = HANDLE::default();

    if unsafe { WlanOpenHandle(2, None, &mut version, &mut handle) } != ERROR_SUCCESS.0 {
        error!("WlanOpenHandle failed");
        return;
    }

    let result = spoof_internal(handle, force_reconnect);

    unsafe { WlanCloseHandle(handle, None) };

    if result.is_err() {
        error!("WiFi spoof routine aborted due to critical failure");
    }

    info!("WiFi spoof routine complete");
}

fn spoof_internal(handle: HANDLE, force_reconnect: bool) -> Result<(), ()> {
    let mut list_ptr: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();

    if unsafe { WlanEnumInterfaces(handle, None, &mut list_ptr) } != ERROR_SUCCESS.0
        || list_ptr.is_null()
    {
        error!("WlanEnumInterfaces failed");
        return Err(());
    }

    let count = unsafe { (*list_ptr).dwNumberOfItems };
    info!("Enumerated {} WLAN interfaces", count);

    for i in 0..count {
        let iface = unsafe { &(*list_ptr).InterfaceInfo[i as usize] };

        if iface.isState != wlan_interface_state_connected {
            debug!("Skipping non-connected interface");
            continue;
        }

        info!("Processing connected interface");

        let (profile_name, bssid) = match query_current_profile(handle, &iface.InterfaceGuid) {
            Some(v) => v,
            None => continue,
        };

        if profile_name.is_empty() {
            continue;
        }

        info!(profile = %profile_name, "Loaded active profile");

        if !disconnect_and_wait(handle, &iface.InterfaceGuid) {
            error!("Failed to disconnect interface before profile update");
            unsafe { WlanFreeMemory(list_ptr as *mut _) };
            return Err(());
        }

        let mut xml = match get_profile_xml(handle, &iface.InterfaceGuid, &profile_name) {
            Some(x) => x,
            None => continue,
        };

        if !ensure_mac_randomization(&mut xml) {
            warn!(profile = %profile_name, "Failed to patch profile XML");
            continue;
        }

        if !validate_profile_xml(&xml) {
            error!("Profile XML validation failed");
            unsafe { WlanFreeMemory(list_ptr as *mut _) };
            return Err(());
        }

        let mut fail_reason = 0u32;

        let set_status = unsafe {
            WlanSetProfile(
                handle,
                &iface.InterfaceGuid,
                0,
                PCWSTR(wide_null(&xml).as_ptr()),
                None,
                true,
                None,
                &mut fail_reason,
            )
        };

        if set_status != ERROR_SUCCESS.0 {
            error!(
                profile = %profile_name,
                status = set_status,
                reason = fail_reason,
                "WlanSetProfile failed"
            );
            unsafe { WlanFreeMemory(list_ptr as *mut _) };
            return Err(());
        }

        info!(profile = %profile_name, "Profile updated successfully");

        if force_reconnect {
            info!("Reconnecting to updated profile");
            if !reconnect_pinned(handle, &iface.InterfaceGuid, &profile_name, &bssid) {
                warn!("Pinned reconnect failed, falling back");

                let mut params: WLAN_CONNECTION_PARAMETERS = unsafe { std::mem::zeroed() };
                params.wlanConnectionMode = wlan_connection_mode_profile;
                let profile_wide = wide_null(&profile_name);
                params.strProfile = PCWSTR(profile_wide.as_ptr());

                unsafe {
                    WlanConnect(handle, &iface.InterfaceGuid, &params, None);
                }
                params.dot11BssType = dot11_BSS_type_infrastructure;

                unsafe {
                    WlanConnect(handle, &iface.InterfaceGuid, &params, None);
                }
            }
        }
    }

    unsafe { WlanFreeMemory(list_ptr as *mut _) };
    Ok(())
}

fn disconnect_and_wait(handle: HANDLE, guid: &GUID) -> bool {
    unsafe {
        WlanDisconnect(handle, guid, None);
    }

    let start = Instant::now();

    while start.elapsed() < DISCONNECT_TIMEOUT {
        if let Some(state) = query_interface_state(handle, guid)
            && state != wlan_interface_state_connected
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    false
}

fn query_interface_state(handle: HANDLE, guid: &GUID) -> Option<WLAN_INTERFACE_STATE> {
    let mut list_ptr: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();

    if unsafe { WlanEnumInterfaces(handle, None, &mut list_ptr) } != ERROR_SUCCESS.0
        || list_ptr.is_null()
    {
        return None;
    }

    let count = unsafe { (*list_ptr).dwNumberOfItems };

    for i in 0..count {
        let iface = unsafe { &(*list_ptr).InterfaceInfo[i as usize] };
        if &iface.InterfaceGuid == guid {
            let state = iface.isState;
            unsafe { WlanFreeMemory(list_ptr as *mut _) };
            return Some(state);
        }
    }

    unsafe { WlanFreeMemory(list_ptr as *mut _) };
    None
}

fn get_profile_xml(handle: HANDLE, guid: &GUID, name: &str) -> Option<String> {
    let mut xml_ptr: PWSTR = PWSTR(std::ptr::null_mut());
    let mut flags = 0u32;

    let name_wide = wide_null(name);

    if unsafe {
        WlanGetProfile(
            handle,
            guid,
            PCWSTR(name_wide.as_ptr()),
            None,
            &mut xml_ptr,
            Some(&mut flags),
            None,
        )
    } != ERROR_SUCCESS.0
        || xml_ptr.0.is_null()
    {
        return None;
    }

    let xml = unsafe { xml_ptr.to_string().unwrap_or_default() };
    unsafe { WlanFreeMemory(xml_ptr.0 as *mut _) };

    Some(xml)
}

fn validate_profile_xml(xml: &str) -> bool {
    xml.contains("<WLANProfile")
        && xml.contains("</WLANProfile>")
        && xml.contains("MacRandomization")
}

fn query_current_profile(handle: HANDLE, guid: &GUID) -> Option<(String, [u8; 6])> {
    let mut size = 0u32;
    let mut conn: *mut WLAN_CONNECTION_ATTRIBUTES = std::ptr::null_mut();
    let mut value_type = WLAN_OPCODE_VALUE_TYPE(0);

    if unsafe {
        WlanQueryInterface(
            handle,
            guid,
            wlan_intf_opcode_current_connection,
            None,
            &mut size,
            &mut conn as *mut _ as *mut *mut _,
            Some(&mut value_type),
        )
    } != ERROR_SUCCESS.0
        || conn.is_null()
    {
        return None;
    }

    let bssid = unsafe { (*conn).wlanAssociationAttributes.dot11Bssid };

    let profile_name = unsafe {
        let ptr = (*conn).strProfileName.as_ptr();
        let slice = std::slice::from_raw_parts(ptr, 256);
        let len = slice.iter().position(|&c| c == 0).unwrap_or(256);
        String::from_utf16_lossy(&slice[..len])
    };

    unsafe { WlanFreeMemory(conn as *mut _) };

    Some((profile_name, bssid))
}

fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => default,
    }
}

fn reconnect_pinned(h: HANDLE, guid: &GUID, profile: &str, bssid: &[u8; 6]) -> bool {
    #[repr(C)]
    struct SingleBssidList {
        header: windows::Win32::NetworkManagement::Ndis::NDIS_OBJECT_HEADER,
        num_entries: u32,
        total_entries: u32,
        bssids: [[u8; 6]; 1],
    }

    let mut list: SingleBssidList = unsafe { std::mem::zeroed() };
    list.header.Type = windows::Win32::NetworkManagement::Ndis::NDIS_OBJECT_TYPE_DEFAULT as u8;
    list.header.Revision = DOT11_BSSID_LIST_REVISION_1 as u8;
    list.header.Size = std::mem::size_of::<SingleBssidList>() as u16;
    list.num_entries = 1;
    list.total_entries = 1;
    list.bssids[0] = *bssid;

    let mut params: WLAN_CONNECTION_PARAMETERS = unsafe { std::mem::zeroed() };
    params.wlanConnectionMode = wlan_connection_mode_profile;

    let profile_wide = wide_null(profile);
    params.strProfile = PCWSTR(profile_wide.as_ptr());

    params.pDesiredBssidList = &list as *const _ as *mut DOT11_BSSID_LIST;
    params.dot11BssType = dot11_BSS_type_infrastructure;

    let status = unsafe { WlanConnect(h, guid, &params, None) };

    status == ERROR_SUCCESS.0
}
