#![allow(dead_code)]

pub fn ensure_mac_randomization(xml: &mut String) -> bool {
    use rand::RngCore;

    const NS: &str = "http://www.microsoft.com/networking/WLAN/profile/v3";

    let seed = rand::thread_rng().next_u32().to_string();
    strip_existing_mac_randomization(xml);
    if !ensure_wlan3_namespace_on_root(xml, NS) {
        return false;
    }

    let block = format!(
        r#"<wlan3:MacRandomization>
<wlan3:enableRandomization>true</wlan3:enableRandomization>
<wlan3:randomizeEveryday>false</wlan3:randomizeEveryday>
<wlan3:randomizationSeed>{}</wlan3:randomizationSeed>
</wlan3:MacRandomization>"#,
        seed
    );

    if let Some(pos) = find_case_insensitive_from(xml, "</WLANProfile>", 0) {
        xml.insert_str(pos, &block);
        true
    } else {
        false
    }
}

fn find_case_insensitive_from(haystack: &str, needle: &str, from: usize) -> Option<usize> {
    if from >= haystack.len() {
        return None;
    }
    let hay = haystack[from..].to_ascii_lowercase();
    let ned = needle.to_ascii_lowercase();
    hay.find(&ned).map(|i| from + i)
}

fn find_char_from(haystack: &str, ch: char, from: usize) -> Option<usize> {
    haystack[from..].find(ch).map(|i| from + i)
}

fn strip_existing_mac_randomization(xml: &mut String) {
    loop {
        let Some(hit) = find_case_insensitive_from(xml, "macrandomization", 0) else {
            return;
        };

        let Some(open_start) = xml[..hit].rfind('<') else {
            return;
        };
        let Some(open_end) = find_char_from(xml, '>', open_start) else {
            return;
        };

        if xml[open_start + 1..].starts_with('/') {
            let next_from = open_end.saturating_add(1);
            if next_from >= xml.len() {
                return;
            }
            if find_case_insensitive_from(xml, "macrandomization", next_from).is_none() {
                return;
            }
            continue;
        }

        let open_tag_body = &xml[open_start + 1..open_end];
        let open_name = open_tag_body
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim();
        if open_name.is_empty() || !open_name.to_ascii_lowercase().ends_with("macrandomization") {
            return;
        }

        let close_tag = format!("</{}>", open_name);
        let search_from = open_end.saturating_add(1);
        let Some(close_start) = find_case_insensitive_from(xml, &close_tag, search_from) else {
            return;
        };
        let close_end = close_start + close_tag.len();

        xml.replace_range(open_start..close_end, "");
    }
}

fn ensure_wlan3_namespace_on_root(xml: &mut String, ns: &str) -> bool {
    let Some(root_start) = find_case_insensitive_from(xml, "<WLANProfile", 0) else {
        return false;
    };
    let Some(root_end) = find_char_from(xml, '>', root_start) else {
        return false;
    };

    let root_tag = &xml[root_start..=root_end];
    if !root_tag.to_ascii_lowercase().contains("xmlns:wlan3=") {
        let ns_attr = format!(r#" xmlns:wlan3="{}""#, ns);
        xml.insert_str(root_end, &ns_attr);
    }

    true
}
