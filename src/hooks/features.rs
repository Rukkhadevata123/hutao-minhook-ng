pub(crate) mod actions;
pub(crate) mod display;
pub(crate) mod ui;

use crate::{
    config::Config,
    hooks::{
        commands::Command,
        signatures::{GameFunction, GameFunction::*},
    },
};
use std::ffi::c_void;

pub type GameThreadPumpFn = for<'a> unsafe fn(&mut GameContext<'a>);
pub type CommandFn = for<'a> unsafe fn(Command, &mut GameContext<'a>) -> bool;

#[derive(Clone, Copy)]
pub struct FeatureCallbacks {
    pub on_game_thread_pump: Option<GameThreadPumpFn>,
    pub on_runtime_command: Option<CommandFn>,
}

#[derive(Clone, Copy)]
pub struct Detour(*mut c_void);

impl Detour {
    pub fn as_ptr(self) -> *mut c_void {
        self.0
    }
}

unsafe impl Sync for Detour {}

#[derive(Clone, Copy)]
pub struct Hook {
    pub function: GameFunction,
    pub detour: Detour,
}

impl Hook {
    const fn new(function: GameFunction, detour: *mut c_void) -> Self {
        Self {
            function,
            detour: Detour(detour),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Feature {
    pub hooks: &'static [Hook],
    pub helpers: &'static [GameFunction],
    pub callbacks: FeatureCallbacks,
}

impl Feature {
    pub const fn new(hooks: &'static [Hook], helpers: &'static [GameFunction]) -> Self {
        Self {
            hooks,
            helpers,
            callbacks: FeatureCallbacks {
                on_game_thread_pump: None,
                on_runtime_command: None,
            },
        }
    }

    pub const fn with_update(
        hooks: &'static [Hook],
        helpers: &'static [GameFunction],
        on_game_thread_pump: GameThreadPumpFn,
    ) -> Self {
        Self {
            hooks,
            helpers,
            callbacks: FeatureCallbacks {
                on_game_thread_pump: Some(on_game_thread_pump),
                on_runtime_command: None,
            },
        }
    }

    pub const fn with_command(
        hooks: &'static [Hook],
        helpers: &'static [GameFunction],
        on_runtime_command: CommandFn,
    ) -> Self {
        Self {
            hooks,
            helpers,
            callbacks: FeatureCallbacks {
                on_game_thread_pump: None,
                on_runtime_command: Some(on_runtime_command),
            },
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RequirementKind {
    Hook,
    Helper,
}

pub struct RequirementEntry {
    pub function: GameFunction,
    pub kind: RequirementKind,
}

pub struct Registry {
    features: &'static [Feature],
    inventory: Vec<RequirementEntry>,
}

impl Registry {
    pub fn new(features: &'static [Feature]) -> Self {
        let mut inventory: Vec<RequirementEntry> = Vec::new();
        for feature in features {
            for hook in feature.hooks {
                merge_requirement(&mut inventory, hook.function, RequirementKind::Hook);
            }
            for function in feature.helpers {
                merge_requirement(&mut inventory, *function, RequirementKind::Helper);
            }
        }

        Self {
            features,
            inventory,
        }
    }

    pub fn features(&self) -> &'static [Feature] {
        self.features
    }

    pub fn inventory(&self) -> &[RequirementEntry] {
        &self.inventory
    }

    pub fn requirements(&self) -> Vec<GameFunction> {
        let mut out = Vec::new();
        for entry in &self.inventory {
            if !out.contains(&entry.function) {
                out.push(entry.function);
            }
        }
        out
    }
}

fn merge_requirement(
    inventory: &mut Vec<RequirementEntry>,
    function: GameFunction,
    kind: RequirementKind,
) {
    if !inventory
        .iter()
        .any(|e| e.function == function && e.kind == kind)
    {
        inventory.push(RequirementEntry { function, kind });
    }
}

pub struct GameContext<'a> {
    pub config: &'a Config,
}

static FEATURES: [Feature; 11] = [
    Feature::new(
        &[Hook::new(
            ShowDamageText,
            ui::hook_show_damage_text as *mut c_void,
        )],
        &[],
    ),
    Feature::new(
        &[Hook::new(
            EventCameraMove,
            ui::hook_event_camera_move as *mut c_void,
        )],
        &[],
    ),
    Feature::new(
        &[Hook::new(OpenTeam, actions::hook_open_team as *mut c_void)],
        &[CheckCanEnter, OpenTeamPage],
    ),
    Feature::with_command(
        &[
            Hook::new(CraftEntry, actions::hook_craft_entry as *mut c_void),
            Hook::new(
                CheckCanOpenMap,
                actions::hook_check_can_open_map as *mut c_void,
            ),
        ],
        &[FindString, CraftEntryPartner],
        actions::on_craft_command,
    ),
    Feature::with_command(
        &[],
        &[FindString, FindGameObject, SetActive],
        ui::on_uid_command,
    ),
    Feature::new(
        &[Hook::new(
            SetupQuestBanner,
            ui::hook_setup_quest_banner as *mut c_void,
        )],
        &[FindString, FindGameObject, SetActive],
    ),
    Feature::new(
        &[Hook::new(
            PlayerPerspective,
            ui::hook_player_perspective as *mut c_void,
        )],
        &[],
    ),
    Feature::with_update(&[], &[SwitchInputDevice], display::update_touch_screen),
    Feature::with_update(
        &[Hook::new(
            GetFrameCount,
            display::hook_get_frame_count as *mut c_void,
        )],
        &[SetFrameCount],
        display::update_frame_rate,
    ),
    Feature::with_update(&[], &[DisplayFog], display::update_fog),
    Feature::new(
        &[Hook::new(
            ChangeFov,
            display::hook_change_fov as *mut c_void,
        )],
        &[],
    ),
];

pub fn all() -> &'static [Feature] {
    &FEATURES
}
