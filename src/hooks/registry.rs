use crate::{
    hooks::{
        features, probes, signatures,
        state::{self, HookBindings},
    },
    logger,
};
use min_hook_rs::{ALL_HOOKS, create_hook, disable_hook, enable_hook};
use std::{ptr, sync::OnceLock};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

static FEATURE_REGISTRY: OnceLock<features::Registry> = OnceLock::new();

fn main_module_rva(addr: *mut std::ffi::c_void) -> usize {
    let base = unsafe { GetModuleHandleW(ptr::null()) } as usize;
    let addr = addr as usize;

    if base != 0 && addr >= base {
        addr - base
    } else {
        addr
    }
}

pub fn feature_registry() -> &'static features::Registry {
    FEATURE_REGISTRY.get_or_init(|| {
        let config = crate::config::get_config();
        let active_features = features::active_features(&config);

        if logger::enabled() {
            let active_ids = active_features
                .iter()
                .map(|feature| format!("{:?}", feature.id))
                .collect::<Vec<_>>()
                .join(",");

            logger::debug!(
                "registry: static={} active=[{}]",
                config.disable_hot_reload as u8,
                active_ids
            );
        }

        features::Registry::new(active_features)
    })
}

pub fn install() -> bool {
    if min_hook_rs::initialize().is_err() {
        logger::debug!("install: minhook initialize fail");
        return false;
    }
    logger::debug!("install: minhook initialize ok");

    let registry = feature_registry();
    let config = crate::config::get_config();
    let probes_enabled = probes::enabled(&config);
    let mut requirements = registry.requirements();
    if probes_enabled {
        for function in probes::requirements() {
            if !requirements.contains(&function) {
                requirements.push(function);
            }
        }
    }
    logger::debug!(
        "install: requirements={} features={} probes={}",
        requirements.len(),
        registry.features().len(),
        if probes_enabled {
            probes::HOOKS.len()
        } else {
            0
        }
    );
    let addresses = signatures::resolve_all(&requirements);
    if logger::enabled() {
        for function in &requirements {
            match addresses.get(*function) {
                Some(addr) => logger::debug!("resolve: function={:?} addr={:p}", function, addr),
                None => logger::debug!("resolve: function={:?} missing", function),
            }
        }
    }

    let mut bindings = HookBindings::default();

    for entry in registry
        .inventory()
        .iter()
        .filter(|entry| entry.kind == features::RequirementKind::Helper)
    {
        if let Some(addr) = addresses.get(entry.function) {
            logger::debug!("helper: function={:?} addr={:p}", entry.function, addr);
            bindings.set_helper(entry.function, addr);
        } else {
            logger::debug!("helper: function={:?} missing", entry.function);
        }
    }

    for feature in registry.features() {
        for hook in feature.hooks {
            let Some(function) = addresses.get(hook.function) else {
                logger::debug!(
                    "hook: feature={:?} function={:?} missing-target skip",
                    feature.id,
                    hook.function
                );
                continue;
            };

            match create_hook(function, hook.detour.as_ptr()) {
                Ok(trampoline) => {
                    logger::debug!(
                        "hook: feature={:?} function={:?} target={:p} target_rva=0x{:x} detour={:p} trampoline={:p} ok",
                        feature.id,
                        hook.function,
                        function,
                        main_module_rva(function),
                        hook.detour.as_ptr(),
                        trampoline
                    );
                    bindings.set_original(hook.function, trampoline);
                }
                Err(_) => {
                    logger::debug!(
                        "hook: feature={:?} function={:?} target={:p} detour={:p} create-fail",
                        feature.id,
                        hook.function,
                        function,
                        hook.detour.as_ptr()
                    );
                }
            }
        }
    }

    if probes_enabled {
        for probe in probes::HOOKS {
            if registry.inventory().iter().any(|entry| {
                entry.kind == features::RequirementKind::Hook && entry.function == probe.function
            }) {
                continue;
            }
            let Some(function) = addresses.get(probe.function) else {
                logger::debug!(
                    "probe-hook: name={} function={:?} missing-target skip",
                    probe.name,
                    probe.function
                );
                continue;
            };

            match create_hook(function, probe.detour) {
                Ok(trampoline) => {
                    logger::debug!(
                        "probe-hook: name={} function={:?} target={:p} target_rva=0x{:x} detour={:p} trampoline={:p} ok",
                        probe.name,
                        probe.function,
                        function,
                        main_module_rva(function),
                        probe.detour,
                        trampoline
                    );
                    bindings.set_original(probe.function, trampoline);
                }
                Err(_) => {
                    logger::debug!(
                        "probe-hook: name={} function={:?} target={:p} detour={:p} create-fail",
                        probe.name,
                        probe.function,
                        function,
                        probe.detour
                    );
                }
            }
        }
    }

    state::publish(bindings);

    if enable_hook(ALL_HOOKS).is_err() {
        logger::debug!("install: enable all fail");
        uninstall();
        return false;
    }

    logger::debug!("install: enable all ok");
    true
}

pub fn uninstall() {
    let _ = disable_hook(ALL_HOOKS);
    let _ = min_hook_rs::uninitialize();
    state::clear();
    crate::hooks::commands::clear();
}
