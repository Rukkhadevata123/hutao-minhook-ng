use std::fs;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{OnceLock, RwLock};
use windows_sys::Win32::Foundation::{HMODULE, MAX_PATH};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};
use windows_sys::Win32::System::WindowsProgramming::{
    GetPrivateProfileIntW, GetPrivateProfileStringW,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_HOME, VK_OEM_1};

#[derive(Debug, Clone)]
pub struct Config {
    // Settings
    pub enable_fps_override: bool,
    pub selected_fps: i32,
    pub enable_fov_override: bool,
    pub fov_value: f32,
    pub use_touch_screen: bool,
    pub disable_hot_reload: bool,

    // Visuals
    pub enable_display_fog_override: bool,
    pub enable_perspective_override: bool,
    pub hide_quest_banner: bool,
    pub hide_uid: bool,
    pub disable_event_camera_move: bool,
    pub disable_show_damage_text: bool,

    // Features
    pub enable_redirect_craft_override: bool,
    pub enable_remove_team_anim: bool,

    // Hotkeys
    pub toggle_key: i32,
    pub craft_key: i32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_fps_override: false,
            selected_fps: 60,
            enable_fov_override: false,
            fov_value: 60.0,
            use_touch_screen: false,
            disable_hot_reload: false,
            enable_display_fog_override: false,
            enable_perspective_override: false,
            hide_quest_banner: false,
            hide_uid: false,
            disable_event_camera_move: false,
            disable_show_damage_text: false,
            enable_redirect_craft_override: false,
            enable_remove_team_anim: false,
            toggle_key: VK_HOME as i32,
            craft_key: VK_OEM_1 as i32,
        }
    }
}

pub static CONFIG: OnceLock<RwLock<Config>> = OnceLock::new();

static CONFIG_PATH: OnceLock<Vec<u16>> = OnceLock::new();
static OFFSET_PATH: OnceLock<PathBuf> = OnceLock::new();
static CURRENT_GAME_VERSION: OnceLock<RwLock<String>> = OnceLock::new();

pub fn setup_config_path(h_module: HMODULE) {
    unsafe {
        let mut path = [0u16; MAX_PATH as usize];
        let len = GetModuleFileNameW(h_module, path.as_mut_ptr(), MAX_PATH);
        if len > 0 {
            let path_slice = &path[..len as usize];
            let path_buf = PathBuf::from(String::from_utf16_lossy(path_slice));
            if let Some(parent) = path_buf.parent() {
                let config_path = parent.join("config.ini");
                let offset_path = parent.join("offset.ini");
                let mut config_path_utf16: Vec<u16> =
                    config_path.to_string_lossy().encode_utf16().collect();
                config_path_utf16.push(0);
                CONFIG_PATH.set(config_path_utf16).ok();
                OFFSET_PATH.set(offset_path).ok();
            }
        }
    }
}

fn to_wstring(str: &str) -> Vec<u16> {
    str.encode_utf16().chain(std::iter::once(0)).collect()
}

fn read_ini_string(path_ptr: *const u16, section: &str, key: &str, default: &str) -> String {
    let mut buf = vec![0u16; MAX_PATH as usize];

    unsafe {
        let len = GetPrivateProfileStringW(
            to_wstring(section).as_ptr(),
            to_wstring(key).as_ptr(),
            to_wstring(default).as_ptr(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            path_ptr,
        );

        String::from_utf16_lossy(&buf[..len as usize])
    }
}

fn parse_game_version(game_config_path: &Path) -> String {
    let Ok(content) = fs::read_to_string(game_config_path) else {
        return String::new();
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }

        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };

        if key.trim().eq_ignore_ascii_case("game_version") {
            let version = value.trim().trim_matches('"');
            let mut parts = version.split('.');
            let major = parts.next().unwrap_or_default();
            let minor = parts.next().unwrap_or_default();

            if major.is_empty() || minor.is_empty() {
                return version.to_string();
            }

            return format!("{}.{}", major, minor);
        }
    }

    String::new()
}

fn refresh_game_version(path_ptr: *const u16) {
    let game_path = read_ini_string(path_ptr, "Settings", "GamePath", "");
    let version = Path::new(&game_path)
        .parent()
        .map(|parent| parse_game_version(&parent.join("config.ini")))
        .unwrap_or_default();

    let version_lock = CURRENT_GAME_VERSION.get_or_init(|| RwLock::new(String::new()));
    if let Ok(mut guard) = version_lock.write() {
        *guard = version;
    }
}

fn current_offset_section() -> String {
    let version = CURRENT_GAME_VERSION
        .get_or_init(|| RwLock::new(String::new()))
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default();

    if version.is_empty() {
        "Offsets".to_string()
    } else {
        format!("{} Offsets", version)
    }
}

fn parse_section_name(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    trimmed.strip_prefix('[')?.strip_suffix(']')
}

fn read_offset_value(contents: &str, section: &str, key: &str) -> Option<String> {
    let mut in_target_section = false;

    for line in contents.lines() {
        if let Some(name) = parse_section_name(line) {
            in_target_section = name == section;
            continue;
        }

        if !in_target_section {
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }

        let Some((current_key, value)) = trimmed.split_once('=') else {
            continue;
        };

        if current_key.trim() == key {
            return Some(value.trim().to_string());
        }
    }

    None
}

fn detect_line_ending(contents: &str) -> &'static str {
    let bytes = contents.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            return if index > 0 && bytes[index - 1] == b'\r' {
                "\r\n"
            } else {
                "\n"
            };
        }
    }

    "\r\n"
}

fn join_lines(lines: &[String], line_ending: &str, trailing_line_ending: bool) -> String {
    let mut contents = lines.join(line_ending);
    if trailing_line_ending {
        contents.push_str(line_ending);
    }
    contents
}

fn upsert_offset_value(contents: &str, section: &str, key: &str, value: &str) -> String {
    let line_ending = detect_line_ending(contents);
    let trailing_line_ending =
        contents.is_empty() || contents.ends_with('\n') || contents.ends_with('\r');
    let mut lines: Vec<String> = contents.lines().map(str::to_string).collect();
    let mut section_start = None;
    let mut section_end = lines.len();

    for (index, line) in lines.iter().enumerate() {
        let Some(name) = parse_section_name(line) else {
            continue;
        };

        if section_start.is_none() {
            if name == section {
                section_start = Some(index);
            }
            continue;
        }

        section_end = index;
        break;
    }

    if let Some(start) = section_start {
        for index in (start + 1)..section_end {
            let trimmed = lines[index].trim();
            if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
                continue;
            }

            let Some((current_key, _)) = trimmed.split_once('=') else {
                continue;
            };

            if current_key.trim() == key {
                lines[index] = format!("{}={}", key, value);
                return join_lines(&lines, line_ending, trailing_line_ending);
            }
        }

        let mut insert_at = section_end;
        while insert_at > start + 1 && lines[insert_at - 1].trim().is_empty() {
            insert_at -= 1;
        }

        lines.insert(insert_at, format!("{}={}", key, value));
        return join_lines(&lines, line_ending, trailing_line_ending);
    }

    let mut new_lines = vec![format!("[{}]", section), format!("{}={}", key, value)];
    if !lines.is_empty() {
        new_lines.push(String::new());
        new_lines.extend(lines);
    }

    join_lines(&new_lines, line_ending, trailing_line_ending)
}

#[allow(non_snake_case)]
pub fn load_config() {
    let path_ptr = match CONFIG_PATH.get() {
        Some(p) => p.as_ptr(),
        None => return,
    };

    let mut new_config = Config::default();

    unsafe {
        let section_settings = to_wstring("Settings");
        let section_visuals = to_wstring("Visuals");
        let section_features = to_wstring("Features");
        let section_hotkeys = to_wstring("Hotkeys");

        // Settings
        new_config.enable_fps_override = GetPrivateProfileIntW(
            section_settings.as_ptr(),
            to_wstring("EnableFPSUnlock").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        new_config.selected_fps = GetPrivateProfileIntW(
            section_settings.as_ptr(),
            to_wstring("TargetFPS").as_ptr(),
            60,
            path_ptr,
        );

        new_config.enable_fov_override = GetPrivateProfileIntW(
            section_settings.as_ptr(),
            to_wstring("EnableFOVModify").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        new_config.use_touch_screen = GetPrivateProfileIntW(
            section_settings.as_ptr(),
            to_wstring("UseTouchScreen").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        new_config.disable_hot_reload = GetPrivateProfileIntW(
            section_settings.as_ptr(),
            to_wstring("DisableHotReload").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        let mut buf = [0u16; 64];
        GetPrivateProfileStringW(
            section_settings.as_ptr(),
            to_wstring("TargetFOV").as_ptr(),
            to_wstring("60.0").as_ptr(),
            buf.as_mut_ptr(),
            64,
            path_ptr,
        );
        let fov_str = String::from_utf16_lossy(&buf);
        // Trim null characters and parse
        if let Some(trimmed) = fov_str.split('\0').next() {
            new_config.fov_value = trimmed.parse().unwrap_or(60.0);
        }

        // Visuals
        new_config.enable_display_fog_override = GetPrivateProfileIntW(
            section_visuals.as_ptr(),
            to_wstring("RemoveFog").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        new_config.enable_perspective_override = GetPrivateProfileIntW(
            section_visuals.as_ptr(),
            to_wstring("RemoveBlur").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        new_config.hide_quest_banner = GetPrivateProfileIntW(
            section_visuals.as_ptr(),
            to_wstring("HideQuestBanner").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        new_config.hide_uid = GetPrivateProfileIntW(
            section_visuals.as_ptr(),
            to_wstring("HideUID").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        new_config.disable_event_camera_move = GetPrivateProfileIntW(
            section_visuals.as_ptr(),
            to_wstring("DisableEventCameraMove").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        new_config.disable_show_damage_text = GetPrivateProfileIntW(
            section_visuals.as_ptr(),
            to_wstring("DisableShowDamageText").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        // Features
        new_config.enable_redirect_craft_override = GetPrivateProfileIntW(
            section_features.as_ptr(),
            to_wstring("RedirectCrafting").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        new_config.enable_remove_team_anim = GetPrivateProfileIntW(
            section_features.as_ptr(),
            to_wstring("RemoveTeamAnimation").as_ptr(),
            0,
            path_ptr,
        ) != 0;

        // Hotkeys
        new_config.toggle_key = GetPrivateProfileIntW(
            section_hotkeys.as_ptr(),
            to_wstring("ToggleKey").as_ptr(),
            VK_HOME as i32,
            path_ptr,
        );

        new_config.craft_key = GetPrivateProfileIntW(
            section_hotkeys.as_ptr(),
            to_wstring("CraftKey").as_ptr(),
            0,
            path_ptr,
        );
    }

    refresh_game_version(path_ptr);

    let config_lock = CONFIG.get_or_init(|| RwLock::new(Config::default()));
    if let Ok(mut write_guard) = config_lock.write() {
        *write_guard = new_config;
    }
}

pub fn get_config() -> Config {
    CONFIG
        .get_or_init(|| RwLock::new(Config::default()))
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default()
}

pub fn load_offsets(key: &str) -> Vec<usize> {
    let Some(path) = OFFSET_PATH.get() else {
        return Vec::new();
    };

    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };

    let section = current_offset_section();
    let Some(value) = read_offset_value(&contents, &section, key) else {
        return Vec::new();
    };

    let base = unsafe { GetModuleHandleW(ptr::null()) } as usize;

    value
        .split(',')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                return None;
            }

            let trimmed = trimmed.trim_start_matches("0x").trim_start_matches("0X");
            usize::from_str_radix(trimmed, 16)
                .ok()
                .map(|rel| base.wrapping_add(rel))
        })
        .collect()
}

pub fn write_offsets(key: &str, addrs: &[usize]) -> bool {
    let path = match OFFSET_PATH.get() {
        Some(p) => p,
        None => return false,
    };

    let base = unsafe { GetModuleHandleW(ptr::null()) } as usize;
    let section = current_offset_section();

    let joined = addrs
        .iter()
        .map(|a| {
            let rel = if *a >= base { a - base } else { *a };
            format!("0x{:x}", rel)
        })
        .collect::<Vec<_>>()
        .join(",");

    let current_contents = fs::read_to_string(path).unwrap_or_default();
    let updated_contents = upsert_offset_value(&current_contents, &section, key, &joined);

    fs::write(path, updated_contents).is_ok()
}
