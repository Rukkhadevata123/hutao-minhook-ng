pub(crate) mod actions;
pub(crate) mod display;
pub(crate) mod ui;

use crate::{
    config::Config,
    hooks::{
        commands::Command,
        pump,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureId {
    PumpDriver,
    ShowDamageText,
    EventCamera,
    Team,
    Craft,
    Uid,
    QuestBanner,
    Perspective,
    TouchScreen,
    FrameRate,
    Fog,
    Fov,
}

#[derive(Clone, Copy)]
pub struct Feature {
    pub id: FeatureId,
    pub hooks: &'static [Hook],
    pub helpers: &'static [GameFunction],
    pub callbacks: FeatureCallbacks,
}

impl Feature {
    pub const fn new(
        id: FeatureId,
        hooks: &'static [Hook],
        helpers: &'static [GameFunction],
    ) -> Self {
        Self {
            id,
            hooks,
            helpers,
            callbacks: FeatureCallbacks {
                on_game_thread_pump: None,
                on_runtime_command: None,
            },
        }
    }

    pub const fn with_update(
        id: FeatureId,
        hooks: &'static [Hook],
        helpers: &'static [GameFunction],
        on_game_thread_pump: GameThreadPumpFn,
    ) -> Self {
        Self {
            id,
            hooks,
            helpers,
            callbacks: FeatureCallbacks {
                on_game_thread_pump: Some(on_game_thread_pump),
                on_runtime_command: None,
            },
        }
    }

    pub const fn with_command(
        id: FeatureId,
        hooks: &'static [Hook],
        helpers: &'static [GameFunction],
        on_runtime_command: CommandFn,
    ) -> Self {
        Self {
            id,
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
    features: Vec<Feature>,
    inventory: Vec<RequirementEntry>,
}

impl Registry {
    pub fn new(features: Vec<Feature>) -> Self {
        debug_assert!(features.iter().enumerate().all(|(index, feature)| {
            !features[..index].iter().any(|prev| prev.id == feature.id)
        }));

        let mut inventory: Vec<RequirementEntry> = Vec::new();
        for feature in &features {
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

    pub fn features(&self) -> &[Feature] {
        &self.features
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

static FEATURES: [Feature; 12] = [
    // Always-on pump driver.
    Feature::new(
        FeatureId::PumpDriver,
        &[Hook::new(
            CameraBrainFlush,
            pump::hook_camera_brain_flush as *mut c_void,
        )],
        &[],
    ),
    Feature::new(
        FeatureId::ShowDamageText,
        &[Hook::new(
            ShowDamageText,
            ui::hook_show_damage_text as *mut c_void,
        )],
        &[],
    ),
    Feature::new(
        FeatureId::EventCamera,
        &[Hook::new(
            EventCameraMove,
            ui::hook_event_camera_move as *mut c_void,
        )],
        &[],
    ),
    Feature::new(
        FeatureId::Team,
        &[Hook::new(OpenTeam, actions::hook_open_team as *mut c_void)],
        &[CheckCanEnter, OpenTeamPage],
    ),
    Feature::with_command(
        FeatureId::Craft,
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
        FeatureId::Uid,
        &[],
        &[FindString, FindGameObject, SetActive],
        ui::on_uid_command,
    ),
    Feature::new(
        FeatureId::QuestBanner,
        &[Hook::new(
            SetupQuestBanner,
            ui::hook_setup_quest_banner as *mut c_void,
        )],
        &[FindString, FindGameObject, SetActive],
    ),
    Feature::new(
        FeatureId::Perspective,
        &[Hook::new(
            PlayerPerspective,
            ui::hook_player_perspective as *mut c_void,
        )],
        &[],
    ),
    Feature::with_update(
        FeatureId::TouchScreen,
        &[],
        &[SwitchInputDevice],
        display::update_touch_screen,
    ),
    Feature::with_update(
        FeatureId::FrameRate,
        &[Hook::new(
            GetFrameCount,
            display::hook_get_frame_count as *mut c_void,
        )],
        &[SetFrameCount],
        display::update_frame_rate,
    ),
    Feature::with_update(FeatureId::Fog, &[], &[DisplayFog], display::update_fog),
    Feature::new(
        FeatureId::Fov,
        &[Hook::new(
            ChangeFov,
            display::hook_change_fov as *mut c_void,
        )],
        &[],
    ),
];

pub fn active_features(config: &Config) -> Vec<Feature> {
    FEATURES
        .iter()
        .copied()
        .filter(|feature| feature_enabled(feature.id, config))
        .collect()
}

fn feature_enabled(id: FeatureId, config: &Config) -> bool {
    if !config.disable_hot_reload {
        return true;
    }

    match id {
        FeatureId::PumpDriver => true,
        FeatureId::ShowDamageText => config.disable_show_damage_text,
        FeatureId::EventCamera => config.disable_event_camera_move,
        FeatureId::Team => config.enable_remove_team_anim,
        FeatureId::Craft => config.enable_redirect_craft_override,
        FeatureId::Uid => config.hide_uid,
        FeatureId::QuestBanner => config.hide_quest_banner,
        FeatureId::Perspective => config.enable_perspective_override,
        FeatureId::TouchScreen => config.use_touch_screen,
        FeatureId::FrameRate => config.enable_fps_override,
        FeatureId::Fog => config.enable_display_fog_override,
        FeatureId::Fov => config.enable_fov_override,
    }
}
