use crate::{
    game::functions,
    hooks::{features::GameContext, pump},
};
use std::{ffi::c_void, sync::Once};

static TOUCH_SCREEN_INIT: Once = Once::new();

pub unsafe extern "system" fn hook_get_frame_count() -> i32 {
    if let Some(ret) = unsafe { functions::original_frame_count() } {
        if ret >= 60 {
            60
        } else if ret >= 45 {
            45
        } else if ret >= 30 {
            30
        } else {
            ret
        }
    } else {
        60
    }
}

pub unsafe extern "system" fn hook_change_fov(a1: *mut c_void, mut change_fov_value: f32) -> i32 {
    let config = unsafe { pump::dispatch() };

    if change_fov_value > 30.0 && config.enable_fov_override {
        change_fov_value = config.fov_value;
    }

    unsafe { functions::original_change_fov(a1, change_fov_value) }.unwrap_or(0)
}

pub(crate) unsafe fn update_touch_screen(ctx: &mut GameContext<'_>) {
    TOUCH_SCREEN_INIT.call_once(|| {
        if ctx.config.use_touch_screen {
            let _ = unsafe { functions::switch_to_touch_screen() };
        }
    });
}

pub(crate) unsafe fn update_frame_rate(ctx: &mut GameContext<'_>) {
    if ctx.config.enable_fps_override {
        let _ = unsafe { functions::set_frame_count(ctx.config.selected_fps) };
    }
}

pub(crate) unsafe fn update_fog(ctx: &mut GameContext<'_>) {
    let _ = unsafe { functions::set_fog_visible(!ctx.config.enable_display_fog_override) };
}
