use crate::{
    hooks::features::{GameContext, Registry},
    logger,
};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    OpenCraft,
    UpdateUidVisibility,
}

static REQUEST_OPEN_CRAFT: AtomicBool = AtomicBool::new(false);
static REQUEST_UID_VISIBILITY_UPDATE: AtomicBool = AtomicBool::new(false);

pub fn request(command: Command) {
    logger::debug!("command: request {:?}", command);
    flag(command).store(true, Ordering::Relaxed);
}

pub fn clear() {
    REQUEST_OPEN_CRAFT.store(false, Ordering::Relaxed);
    REQUEST_UID_VISIBILITY_UPDATE.store(false, Ordering::Relaxed);
}

pub(crate) unsafe fn drain(ctx: &mut GameContext, registry: &Registry) {
    for command in [Command::OpenCraft, Command::UpdateUidVisibility] {
        if !flag(command).swap(false, Ordering::Relaxed) {
            continue;
        }

        let mut handled_by = None;
        for feature in registry.features() {
            let Some(on_runtime_command) = feature.callbacks.on_runtime_command else {
                continue;
            };

            if unsafe { on_runtime_command(command, ctx) } {
                handled_by = Some(feature.id);
                break;
            }
        }

        match handled_by {
            Some(feature_id) => {
                logger::debug!("command: {:?} handled_by={:?}", command, feature_id)
            }
            None => logger::debug!("command: {:?} unhandled", command),
        }
    }
}

fn flag(command: Command) -> &'static AtomicBool {
    match command {
        Command::OpenCraft => &REQUEST_OPEN_CRAFT,
        Command::UpdateUidVisibility => &REQUEST_UID_VISIBILITY_UPDATE,
    }
}
