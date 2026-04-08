mod config;
mod hooks;
mod hutao_seh;
mod scanner;

use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::Foundation::{HMODULE, TRUE};
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::System::Threading::{CreateThread, Sleep};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;
use windows_sys::core::BOOL;

use crate::config::{get_config, load_config, setup_config_path};
use crate::hooks::{
    init_hooks, is_game_update_init, request_open_craft, request_update_uid_visibility,
};

/// The main worker thread function.
/// Corresponds to the `Run` function in the C++ version.
unsafe extern "system" fn run(h_module: *mut c_void) -> u32 {
    unsafe {
        // Setup config path based on DLL location
        setup_config_path(h_module as HMODULE);

        // Load initial configuration
        load_config();

        // Initialize Hooks (Scan patterns and create hooks)
        if !init_hooks() {
            // Failed to initialize hooks (e.g., patterns not found)
            return 0;
        }

        // Wait for GameUpdate to be called (indicates game logic is running)
        while !is_game_update_init() {
            Sleep(1000);
        }

        // Update UID after the main game loop has started.
        request_update_uid_visibility();

        // Main loop for hotkey monitoring
        loop {
            let config = get_config();

            // Check for Toggle Key (Default VK_HOME)
            // GetAsyncKeyState returns i16, bit 15 (0x8000) indicates the key is currently down.
            if (GetAsyncKeyState(config.toggle_key) as u16 & 0x8000) != 0 {
                load_config();
                request_update_uid_visibility();
                // Simple debounce to prevent multiple reloads per press
                Sleep(500);
            }

            // Check for Craft Key
            if config.craft_key != 0 && (GetAsyncKeyState(config.craft_key) as u16 & 0x8000) != 0 {
                request_open_craft();
                // Debounce to prevent opening multiple pages at once
                Sleep(500);
            }

            Sleep(100);
        }
    }
}

/// Standard DLL Entry Point
/// # Safety
/// This function is called by the Windows loader when the DLL is loaded or unloaded.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(hinst: HMODULE, reason: u32, _reserved: *mut c_void) -> BOOL {
    unsafe {
        match reason {
            DLL_PROCESS_ATTACH => {
                // Disable thread library calls for optimization
                DisableThreadLibraryCalls(hinst);

                // Create the main worker thread
                // We pass hinst as the parameter so we can find the config file path later
                CreateThread(ptr::null(), 0, Some(run), hinst, 0, ptr::null_mut());
            }
            DLL_PROCESS_DETACH => {
                // Cleanup hooks when DLL is unloaded
                let _ = min_hook_rs::disable_hook(min_hook_rs::ALL_HOOKS);
                let _ = min_hook_rs::uninitialize();
            }
            _ => {}
        }
        TRUE
    }
}
