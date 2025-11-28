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
use crate::hooks::{init_hooks, is_game_update_init};

/// The main worker thread function.
/// Corresponds to the `Run` function in the C++ version.
unsafe extern "system" fn run(h_module: *mut c_void) -> u32 {
    unsafe {
        // 1. Setup config path based on DLL location
        setup_config_path(h_module as HMODULE);

        // 2. Load initial configuration
        load_config();

        // 3. Initialize Hooks (Scan patterns and create hooks)
        if !init_hooks() {
            // Failed to initialize hooks (e.g., patterns not found)
            return 0;
        }

        // 4. Wait for GameUpdate to be called (indicates game logic is running)
        while !is_game_update_init() {
            Sleep(1000);
        }

        // 5. Main loop for hotkey monitoring
        loop {
            let config = get_config();

            // Check for Toggle Key (Default VK_HOME)
            // GetAsyncKeyState returns i16, bit 15 (0x8000) indicates the key is currently down.
            if (GetAsyncKeyState(config.toggle_key) as u16 & 0x8000) != 0 {
                load_config();
                // Simple debounce to prevent multiple reloads per press
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
