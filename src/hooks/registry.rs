use crate::hooks::{
    features, signatures,
    state::{self, HookBindings},
};
use min_hook_rs::{ALL_HOOKS, create_hook, disable_hook, enable_hook};
use std::sync::OnceLock;

static FEATURE_REGISTRY: OnceLock<features::Registry> = OnceLock::new();

pub fn feature_registry() -> &'static features::Registry {
    FEATURE_REGISTRY.get_or_init(|| {
        let config = crate::config::get_config();
        features::Registry::new(features::active_features(&config))
    })
}

pub fn install() -> bool {
    if min_hook_rs::initialize().is_err() {
        return false;
    }

    let registry = feature_registry();
    let addresses = signatures::resolve_all(&registry.requirements());
    let mut bindings = HookBindings::default();

    for entry in registry
        .inventory()
        .iter()
        .filter(|entry| entry.kind == features::RequirementKind::Helper)
    {
        if let Some(addr) = addresses.get(entry.function) {
            bindings.set_helper(entry.function, addr);
        }
    }

    for feature in registry.features() {
        for hook in feature.hooks {
            let Some(function) = addresses.get(hook.function) else {
                continue;
            };

            if let Ok(trampoline) = create_hook(function, hook.detour.as_ptr()) {
                bindings.set_original(hook.function, trampoline);
            }
        }
    }

    state::publish(bindings);

    if enable_hook(ALL_HOOKS).is_err() {
        uninstall();
        return false;
    }

    true
}

pub fn uninstall() {
    let _ = disable_hook(ALL_HOOKS);
    let _ = min_hook_rs::uninitialize();
    state::clear();
    crate::hooks::commands::clear();
}
