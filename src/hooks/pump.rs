use crate::{
    config::get_config,
    game::functions,
    hooks::{commands, features::GameContext, registry, state},
};
use std::ffi::c_void;

pub unsafe fn dispatch() {
    state::mark_game_update_ready();

    let config = get_config();
    let mut ctx = GameContext { config: &config };
    let registry = registry::feature_registry();

    unsafe { commands::drain(&mut ctx, registry) };

    for feature in registry.features() {
        if let Some(on_game_thread_pump) = feature.callbacks.on_game_thread_pump {
            unsafe { on_game_thread_pump(&mut ctx) };
        }
    }
}

/// Per-frame game-thread pump driver.
pub unsafe extern "system" fn hook_camera_brain_flush(a1: *mut c_void) -> i64 {
    unsafe { dispatch() };
    unsafe { functions::original_camera_brain_flush(a1) }.unwrap_or(0)
}
