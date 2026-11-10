use crate::hooks::signatures::GameFunction;
use std::ffi::c_void;

pub struct ProbeHook {
    pub name: &'static str,
    pub function: GameFunction,
    pub detour: *mut c_void,
}

unsafe impl Sync for ProbeHook {}

pub const HOOKS: &[ProbeHook] = &[];

pub fn enabled(config: &crate::config::Config) -> bool {
    config.debug_mode && !HOOKS.is_empty()
}

pub fn requirements() -> impl Iterator<Item = GameFunction> + 'static {
    HOOKS.iter().map(|hook| hook.function)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn probe_framework_stays_disabled_without_hooks() {
        assert!(HOOKS.is_empty());
        assert_eq!(requirements().count(), 0);

        let mut config = Config::default();
        assert!(!enabled(&config));

        config.debug_mode = true;
        assert!(!enabled(&config));
    }
}
