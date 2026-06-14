use crate::{
    config::{get_config, load_config, setup_config_path},
    hooks::{
        self,
        commands::{self, Command},
    },
};
use std::ffi::c_void;
use windows_sys::Win32::{
    Foundation::HMODULE, System::Threading::Sleep, UI::Input::KeyboardAndMouse::GetAsyncKeyState,
};

pub unsafe extern "system" fn run(h_module: *mut c_void) -> u32 {
    unsafe {
        setup_config_path(h_module as HMODULE);
        load_config();

        if !hooks::install() {
            return 0;
        }

        while !hooks::is_game_update_ready() {
            Sleep(1000);
        }

        commands::request(Command::UpdateUidVisibility);

        loop {
            let config = get_config();

            if (GetAsyncKeyState(config.toggle_key) as u16 & 0x8000) != 0 {
                load_config();
                commands::request(Command::UpdateUidVisibility);
                Sleep(500);
            }

            if config.craft_key != 0 && (GetAsyncKeyState(config.craft_key) as u16 & 0x8000) != 0 {
                commands::request(Command::OpenCraft);
                Sleep(500);
            }

            Sleep(100);
        }
    }
}
