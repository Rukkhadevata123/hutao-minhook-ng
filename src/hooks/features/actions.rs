use crate::{
    game::functions,
    hooks::{features::GameContext, commands::Command},
};
use std::ffi::c_void;

pub unsafe fn open_synthesis_page() -> bool {
    unsafe { functions::open_synthesis_page() }
}

pub unsafe extern "system" fn hook_check_can_open_map(p_this: *mut c_void) -> bool {
    let config = crate::config::get_config();
    if config.enable_redirect_craft_override {
        return false;
    }

    unsafe { functions::original_check_can_open_map(p_this) }.unwrap_or(false)
}

pub unsafe extern "system" fn hook_craft_entry(p_this: *mut c_void) {
    let config = crate::config::get_config();

    if config.enable_redirect_craft_override && unsafe { open_synthesis_page() } {
        return;
    }

    let _ = unsafe { functions::original_craft_entry(p_this) };
}

pub unsafe extern "system" fn hook_open_team() {
    let config = crate::config::get_config();

    if config.enable_remove_team_anim
        && unsafe { functions::can_enter() }.unwrap_or(false)
        && unsafe { functions::open_team_page_accordingly(false) }
    {
        return;
    }

    let _ = unsafe { functions::original_open_team() };
}

pub(crate) unsafe fn on_craft_command(command: Command, _ctx: &mut GameContext<'_>) -> bool {
    if command != Command::OpenCraft {
        return false;
    }

    let _ = unsafe { open_synthesis_page() };
    true
}
