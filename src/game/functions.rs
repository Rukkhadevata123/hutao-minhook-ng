use crate::game::{
    abi::{
        CameraBrainFlushFn, ChangeFovFn, CheckCanEnterFn, CheckCanOpenMapFn, CraftEntryFn,
        CraftEntryPartnerFn, DisplayFogFn, EventCameraMoveFn, FindGameObjectFn, FindStringFn,
        GetFrameCountFn, OpenTeamFn, OpenTeamPageAccordinglyFn, PlayerPerspectiveFn, SetActiveFn,
        SetFrameCountFn, SetupQuestBannerFn, ShowDamageTextFn, SwitchInputDeviceToTouchScreenFn,
    },
    il2cpp::Il2CppString,
};
use crate::hooks::{signatures::GameFunction, state};
use crate::hutao_seh::try_seh;
use crate::logger;
use std::ffi::{c_char, c_void};
use std::ptr;

fn logged<R>(name: &str, f: impl FnMut() -> R) -> Option<R> {
    try_seh(f)
        .inspect_err(|code| {
            logger::debug!("{name}: game call faulted exception={code:#x}");
        })
        .ok()
}

fn silent<R>(f: impl FnMut() -> R) -> Option<R> {
    try_seh(f).ok()
}

pub unsafe fn original_frame_count() -> Option<i32> {
    let ptr = state::original(GameFunction::GetFrameCount);
    if ptr.is_null() {
        return None;
    }
    let original: GetFrameCountFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { original() })
}

pub unsafe fn set_frame_count(value: i32) -> bool {
    let ptr = state::helper(GameFunction::SetFrameCount);
    if ptr.is_null() {
        return false;
    }
    let f: SetFrameCountFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { f(value) }).is_some()
}

pub unsafe fn original_change_fov(a1: *mut c_void, value: f32) -> Option<i32> {
    let ptr = state::original(GameFunction::ChangeFov);
    if ptr.is_null() {
        return None;
    }
    let original: ChangeFovFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { original(a1, value) })
}

pub unsafe fn original_camera_brain_flush(a1: *mut c_void) -> Option<i64> {
    let ptr = state::original(GameFunction::CameraBrainFlush);
    if ptr.is_null() {
        return None;
    }
    let original: CameraBrainFlushFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { original(a1) })
}

pub unsafe fn set_fog_visible(visible: bool) -> bool {
    let ptr = state::helper(GameFunction::DisplayFog);
    if ptr.is_null() {
        return false;
    }
    let display_fog: DisplayFogFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { display_fog(visible) }).is_some()
}

pub unsafe fn switch_to_touch_screen() -> bool {
    let ptr = state::helper(GameFunction::SwitchInputDevice);
    if ptr.is_null() {
        return false;
    }
    let switch_input: SwitchInputDeviceToTouchScreenFn = unsafe { std::mem::transmute(ptr) };
    logged("switch_to_touch_screen", || unsafe {
        switch_input(ptr::null_mut())
    })
    .is_some()
}

pub unsafe fn original_player_perspective(p_this: *mut c_void, display: bool) -> bool {
    let ptr = state::original(GameFunction::PlayerPerspective);
    if ptr.is_null() {
        return false;
    }
    let original: PlayerPerspectiveFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { original(p_this, display) }).is_some()
}

pub unsafe fn original_setup_quest_banner(p_this: *mut c_void) -> bool {
    let ptr = state::original(GameFunction::SetupQuestBanner);
    if ptr.is_null() {
        return false;
    }
    let original: SetupQuestBannerFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { original(p_this) }).is_some()
}

pub unsafe fn original_event_camera_move(p_this: *mut c_void, event: *mut c_void) -> Option<bool> {
    let ptr = state::original(GameFunction::EventCameraMove);
    if ptr.is_null() {
        return None;
    }
    let original: EventCameraMoveFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { original(p_this, event) })
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn original_show_damage_text(
    p_this: *mut c_void,
    type_: i32,
    damage_type: i32,
    show_type: i32,
    damage: f32,
    show_text: *mut Il2CppString,
    world_pos: *mut c_void,
    attackee: *mut c_void,
    element_reaction_type: i32,
    extra_bool: bool,
    extra_float: f32,
) -> bool {
    let ptr = state::original(GameFunction::ShowDamageText);
    if ptr.is_null() {
        return false;
    }
    let original: ShowDamageTextFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe {
        original(
            p_this,
            type_,
            damage_type,
            show_type,
            damage,
            show_text,
            world_pos,
            attackee,
            element_reaction_type,
            extra_bool,
            extra_float,
        )
    })
    .is_some()
}

pub unsafe fn original_craft_entry(p_this: *mut c_void) -> bool {
    let ptr = state::original(GameFunction::CraftEntry);
    if ptr.is_null() {
        return false;
    }
    let original: CraftEntryFn = unsafe { std::mem::transmute(ptr) };
    logged("original_craft_entry", || unsafe { original(p_this) }).is_some()
}

pub unsafe fn original_check_can_open_map(p_this: *mut c_void) -> Option<bool> {
    let ptr = state::original(GameFunction::CheckCanOpenMap);
    if ptr.is_null() {
        return None;
    }
    let original: CheckCanOpenMapFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { original(p_this) })
}

pub unsafe fn original_open_team() -> bool {
    let ptr = state::original(GameFunction::OpenTeam);
    if ptr.is_null() {
        return false;
    }
    let original: OpenTeamFn = unsafe { std::mem::transmute(ptr) };
    logged("original_open_team", || unsafe { original() }).is_some()
}

pub unsafe fn open_synthesis_page() -> bool {
    let partner_ptr = state::helper(GameFunction::CraftEntryPartner);
    if partner_ptr.is_null() {
        return false;
    }
    let Some(page) = (unsafe { find_string(b"SynthesisPage\0") }) else {
        return false;
    };
    let craft_entry_partner: CraftEntryPartnerFn = unsafe { std::mem::transmute(partner_ptr) };
    logged("open_synthesis_page", || unsafe {
        craft_entry_partner(
            page,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
    })
    .is_some()
}

pub unsafe fn can_enter() -> Option<bool> {
    let ptr = state::helper(GameFunction::CheckCanEnter);
    if ptr.is_null() {
        return None;
    }
    let check_can_enter: CheckCanEnterFn = unsafe { std::mem::transmute(ptr) };
    logged("can_enter", || unsafe { check_can_enter() })
}

pub unsafe fn open_team_page_accordingly(animated: bool) -> bool {
    let ptr = state::helper(GameFunction::OpenTeamPage);
    if ptr.is_null() {
        return false;
    }
    let f: OpenTeamPageAccordinglyFn = unsafe { std::mem::transmute(ptr) };
    logged("open_team_page_accordingly", || unsafe { f(animated) }).is_some()
}

pub(crate) unsafe fn find_string(value: &[u8]) -> Option<*mut Il2CppString> {
    let ptr = state::helper(GameFunction::FindString);
    if ptr.is_null() {
        return None;
    }
    let f: FindStringFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { f(value.as_ptr() as *const c_char) }).filter(|string| !string.is_null())
}

pub(crate) unsafe fn find_game_object(value: *mut Il2CppString) -> Option<*mut c_void> {
    let ptr = state::helper(GameFunction::FindGameObject);
    if ptr.is_null() {
        return None;
    }
    let f: FindGameObjectFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { f(value) }).filter(|object| !object.is_null())
}

pub(crate) unsafe fn set_active(object: *mut c_void, active: bool) -> bool {
    let ptr = state::helper(GameFunction::SetActive);
    if ptr.is_null() {
        return false;
    }
    let f: SetActiveFn = unsafe { std::mem::transmute(ptr) };
    silent(|| unsafe { f(object, active) }).is_some()
}

pub(crate) fn has_unity_object_helpers() -> bool {
    !state::helper(GameFunction::FindString).is_null()
        && !state::helper(GameFunction::FindGameObject).is_null()
        && !state::helper(GameFunction::SetActive).is_null()
}
