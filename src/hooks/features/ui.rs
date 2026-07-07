use crate::{
    game::{functions, il2cpp::Il2CppString},
    hooks::{commands::Command, features::GameContext},
};
use std::ffi::c_void;

const UID_PATH: &[u8] = b"/BetaWatermarkCanvas(Clone)/Panel/TxtUID\0";

pub unsafe extern "system" fn hook_setup_quest_banner(p_this: *mut c_void) {
    let config = crate::config::get_config();

    if config.hide_quest_banner
        && unsafe {
            hide_path(b"Canvas/Pages/InLevelMapPage/GrpMap/GrpPointTips/Layout/QuestBanner\0")
        }
    {
        return;
    }

    let _ = unsafe { functions::original_setup_quest_banner(p_this) };
}

pub unsafe extern "system" fn hook_event_camera_move(
    p_this: *mut c_void,
    event: *mut c_void,
) -> bool {
    let config = crate::config::get_config();
    if config.disable_event_camera_move {
        return true;
    }

    unsafe { functions::original_event_camera_move(p_this, event) }.unwrap_or(true)
}

#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn hook_show_damage_text(
    p_this: *mut c_void,
    type_: i32,
    damage_type: i32,
    show_type: i32,
    damage: f32,
    show_text: *mut Il2CppString,
    world_pos: *mut c_void,
    attackee: *mut c_void,
    element_reaction_type: i32,
) {
    let config = crate::config::get_config();
    if config.disable_show_damage_text {
        return;
    }

    let _ = unsafe {
        functions::original_show_damage_text(
            p_this,
            type_,
            damage_type,
            show_type,
            damage,
            show_text,
            world_pos,
            attackee,
            element_reaction_type,
        )
    };
}

pub unsafe extern "system" fn hook_player_perspective(p_this: *mut c_void, display: bool) {
    let config = crate::config::get_config();
    if config.enable_perspective_override {
        return;
    }

    let _ = unsafe { functions::original_player_perspective(p_this, display) };
}

pub(crate) unsafe fn update_uid_visibility(ctx: &GameContext<'_>) -> bool {
    if ctx.config.hide_uid {
        unsafe { hide_path(UID_PATH) }
    } else {
        unsafe { show_path(UID_PATH) }
    }
}

pub(crate) unsafe fn on_uid_command(command: Command, ctx: &mut GameContext<'_>) -> bool {
    if command != Command::UpdateUidVisibility {
        return false;
    }

    let _ = unsafe { update_uid_visibility(ctx) };
    true
}

unsafe fn hide_path(path: &[u8]) -> bool {
    unsafe { set_path_active(path, false) }
}

unsafe fn show_path(path: &[u8]) -> bool {
    unsafe { set_path_active(path, true) }
}

unsafe fn set_path_active(path: &[u8], active: bool) -> bool {
    if !functions::has_unity_object_helpers() {
        return false;
    }

    let Some(path) = (unsafe { functions::find_string(path) }) else {
        return false;
    };

    let Some(game_object) = (unsafe { functions::find_game_object(path) }) else {
        return false;
    };

    unsafe { functions::set_active(game_object, active) }
}
