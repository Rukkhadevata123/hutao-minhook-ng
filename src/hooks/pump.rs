use crate::{
    config::{Config, get_config},
    hooks::{features::GameContext, registry, commands, state},
};

pub unsafe fn dispatch() -> Config {
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

    config
}
