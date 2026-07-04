use crate::{
    config::{get_config, load_config, setup_config_path},
    hooks::{
        self,
        commands::{self, Command},
    },
    logger,
};
use std::ffi::c_void;
use windows_sys::Win32::{
    Foundation::HMODULE,
    System::Threading::{GetCurrentProcessId, Sleep},
    UI::{
        Input::KeyboardAndMouse::GetAsyncKeyState,
        WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId},
    },
};

fn is_game_foreground() -> bool {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.is_null() {
            return false;
        }

        let mut foreground_process_id = 0;
        if GetWindowThreadProcessId(hwnd, &mut foreground_process_id) == 0 {
            return false;
        }

        foreground_process_id == GetCurrentProcessId()
    }
}

pub unsafe extern "system" fn run(h_module: *mut c_void) -> u32 {
    unsafe {
        setup_config_path(h_module as HMODULE);
        logger::setup_path(h_module as HMODULE);
        load_config();
        logger::start_session();

        if !hooks::install() {
            return 0;
        }

        while !hooks::is_game_update_ready() {
            Sleep(1000);
        }
        logger::debug!("runtime: game update ready");

        commands::request(Command::UpdateUidVisibility);

        loop {
            let config = get_config();

            if (GetAsyncKeyState(config.toggle_key) as u16 & 0x8000) != 0 {
                load_config();
                logger::debug!("config: reload");
                commands::request(Command::UpdateUidVisibility);
                Sleep(500);
            }

            if config.craft_key != 0
                && is_game_foreground()
                && (GetAsyncKeyState(config.craft_key) as u16 & 0x8000) != 0
            {
                commands::request(Command::OpenCraft);
                Sleep(500);
            }

            Sleep(100);
        }
    }
}
