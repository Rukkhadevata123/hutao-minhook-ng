use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};
use windows_sys::Win32::Foundation::{HMODULE, MAX_PATH};
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::WindowsProgramming::{
    GetPrivateProfileIntW, GetPrivateProfileStringW,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_HOME;

#[derive(Debug, Clone)]
pub struct Config {
    // Settings
    pub enable_fps_override: bool,
    pub selected_fps: i32,
    pub enable_fov_override: bool,
    pub fov_value: f32,

    // Visuals
    pub enable_display_fog_override: bool,
    pub enable_perspective_override: bool,
    pub enable_fix_low_fov: bool,

    // Features
    pub enable_redirect_craft_override: bool,
    pub enable_remove_team_anim: bool,

    // Hotkeys
    pub toggle_key: i32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_fps_override: false,
            selected_fps: 60,
            enable_fov_override: false,
            fov_value: 60.0,
            enable_display_fog_override: false,
            enable_perspective_override: false,
            enable_fix_low_fov: false,
            enable_redirect_craft_override: false,
            enable_remove_team_anim: false,
            toggle_key: VK_HOME as i32,
        }
    }
}

// Global configuration instance protected by a Read-Write Lock
pub static CONFIG: OnceLock<RwLock<Config>> = OnceLock::new();

// Store the path to the config file
static CONFIG_PATH: OnceLock<Vec<u16>> = OnceLock::new();

/// Initializes the configuration path based on the DLL location.
pub fn setup_config_path(h_module: HMODULE) {
    unsafe {
        let mut path = [0u16; MAX_PATH as usize];
        let len = GetModuleFileNameW(h_module, path.as_mut_ptr(), MAX_PATH);
        if len > 0 {
            let path_slice = &path[..len as usize];
            let path_buf = PathBuf::from(String::from_utf16_lossy(path_slice));
            if let Some(parent) = path_buf.parent() {
                let config_path = parent.join("config.ini");
                // Convert back to UTF-16 null-terminated vector for Windows APIs
                let mut config_path_utf16: Vec<u16> =
                    config_path.to_string_lossy().encode_utf16().collect();
                config_path_utf16.push(0);
                CONFIG_PATH.set(config_path_utf16).ok();
            }
        }
    }
}

/// Helper to convert Rust string to wide string (UTF-16)
fn to_wstring(str: &str) -> Vec<u16> {
    str.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Loads configuration from the INI file.
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
        ) as i32;

        new_config.enable_fov_override = GetPrivateProfileIntW(
            section_settings.as_ptr(),
            to_wstring("EnableFOVModify").as_ptr(),
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

        new_config.enable_fix_low_fov = GetPrivateProfileIntW(
            section_visuals.as_ptr(),
            to_wstring("FixLowFOV").as_ptr(),
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
        ) as i32;
    }

    // Update the global config
    let config_lock = CONFIG.get_or_init(|| RwLock::new(Config::default()));
    if let Ok(mut write_guard) = config_lock.write() {
        *write_guard = new_config;
    }
}

/// Helper to get a copy of the current configuration
pub fn get_config() -> Config {
    CONFIG
        .get_or_init(|| RwLock::new(Config::default()))
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default()
}
