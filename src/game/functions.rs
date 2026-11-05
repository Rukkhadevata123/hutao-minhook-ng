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

unsafe fn logged<F>(name: &str, f: F) -> bool
where
    F: FnMut(),
{
    match try_seh(f) {
        Ok(()) => true,
        Err(e) => {
            logger::debug!("{name}: game call faulted exception={e:#x}");
            false
        }
    }
}

unsafe fn logged_val<F, R>(name: &str, f: F) -> Option<R>
where
    F: FnMut() -> R,
{
    match try_seh(f) {
        Ok(v) => Some(v),
        Err(e) => {
            logger::debug!("{name}: game call faulted exception={e:#x}");
            None
        }
    }
}

unsafe fn silent<F>(f: F) -> bool
where
    F: FnMut(),
{
    try_seh(f).is_ok()
}

unsafe fn silent_val<F, R>(f: F) -> Option<R>
where
    F: FnMut() -> R,
{
    try_seh(f).ok()
}

pub unsafe fn original_frame_count() -> Option<i32> {
    let ptr = state::original(GameFunction::GetFrameCount);
    if ptr.is_null() {
        return None;
    }
    let original: GetFrameCountFn = unsafe { std::mem::transmute(ptr) };
    unsafe { silent_val(move || original()) }
}

pub unsafe fn set_frame_count(value: i32) -> bool {
    let ptr = state::helper(GameFunction::SetFrameCount);
    if ptr.is_null() {
        return false;
    }
    let f: SetFrameCountFn = unsafe { std::mem::transmute(ptr) };
    unsafe {
        silent(move || {
            f(value);
        })
    }
}

pub unsafe fn original_change_fov(a1: *mut c_void, value: f32) -> Option<i32> {
    let ptr = state::original(GameFunction::ChangeFov);
    if ptr.is_null() {
        return None;
    }
    let original: ChangeFovFn = unsafe { std::mem::transmute(ptr) };
    unsafe { silent_val(move || original(a1, value)) }
}

pub unsafe fn original_camera_brain_flush(a1: *mut c_void) -> Option<i64> {
    let ptr = state::original(GameFunction::CameraBrainFlush);
    if ptr.is_null() {
        return None;
    }
    let original: CameraBrainFlushFn = unsafe { std::mem::transmute(ptr) };
    unsafe { silent_val(move || original(a1)) }
}

pub unsafe fn set_fog_visible(visible: bool) -> bool {
    let ptr = state::helper(GameFunction::DisplayFog);
    if ptr.is_null() {
        return false;
    }
    let display_fog: DisplayFogFn = unsafe { std::mem::transmute(ptr) };
    unsafe { silent(move || display_fog(visible)) }
}

pub unsafe fn switch_to_touch_screen() -> bool {
    let ptr = state::helper(GameFunction::SwitchInputDevice);
    if ptr.is_null() {
        return false;
    }
    let switch_input: SwitchInputDeviceToTouchScreenFn = unsafe { std::mem::transmute(ptr) };
    unsafe {
        logged("switch_to_touch_screen", move || {
            switch_input(ptr::null_mut())
        })
    }
}

pub unsafe fn original_player_perspective(p_this: *mut c_void, display: bool) -> bool {
    let ptr = state::original(GameFunction::PlayerPerspective);
    if ptr.is_null() {
        return false;
    }
    let original: PlayerPerspectiveFn = unsafe { std::mem::transmute(ptr) };
    unsafe { silent(move || original(p_this, display)) }
}

pub unsafe fn original_setup_quest_banner(p_this: *mut c_void) -> bool {
    let ptr = state::original(GameFunction::SetupQuestBanner);
    if ptr.is_null() {
        return false;
    }
    let original: SetupQuestBannerFn = unsafe { std::mem::transmute(ptr) };
    unsafe { silent(move || original(p_this)) }
}

pub unsafe fn original_event_camera_move(p_this: *mut c_void, event: *mut c_void) -> Option<bool> {
    let ptr = state::original(GameFunction::EventCameraMove);
    if ptr.is_null() {
        return None;
    }
    let original: EventCameraMoveFn = unsafe { std::mem::transmute(ptr) };
    unsafe { silent_val(move || original(p_this, event)) }
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
) -> bool {
    let ptr = state::original(GameFunction::ShowDamageText);
    if ptr.is_null() {
        return false;
    }
    let original: ShowDamageTextFn = unsafe { std::mem::transmute(ptr) };
    unsafe {
        silent(move || {
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
            )
        })
    }
}

pub unsafe fn original_craft_entry(p_this: *mut c_void) -> bool {
    let ptr = state::original(GameFunction::CraftEntry);
    if ptr.is_null() {
        return false;
    }
    let original: CraftEntryFn = unsafe { std::mem::transmute(ptr) };
    unsafe { logged("original_craft_entry", move || original(p_this)) }
}

pub unsafe fn original_check_can_open_map(p_this: *mut c_void) -> Option<bool> {
    let ptr = state::original(GameFunction::CheckCanOpenMap);
    if ptr.is_null() {
        return None;
    }
    let original: CheckCanOpenMapFn = unsafe { std::mem::transmute(ptr) };
    unsafe { silent_val(move || original(p_this)) }
}

pub unsafe fn original_open_team() -> bool {
    let ptr = state::original(GameFunction::OpenTeam);
    if ptr.is_null() {
        return false;
    }
    let original: OpenTeamFn = unsafe { std::mem::transmute(ptr) };
    unsafe { logged("original_open_team", move || original()) }
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
    unsafe {
        logged("open_synthesis_page", move || {
            craft_entry_partner(
                page,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
        })
    }
}

pub unsafe fn can_enter() -> Option<bool> {
    let ptr = state::helper(GameFunction::CheckCanEnter);
    if ptr.is_null() {
        return None;
    }
    let check_can_enter: CheckCanEnterFn = unsafe { std::mem::transmute(ptr) };
    unsafe { logged_val("can_enter", move || check_can_enter()) }
}

pub unsafe fn open_team_page_accordingly(animated: bool) -> bool {
    let ptr = state::helper(GameFunction::OpenTeamPage);
    if ptr.is_null() {
        return false;
    }
    let f: OpenTeamPageAccordinglyFn = unsafe { std::mem::transmute(ptr) };
    unsafe {
        logged("open_team_page_accordingly", move || {
            f(animated);
        })
    }
}

pub(crate) unsafe fn find_string(value: &[u8]) -> Option<*mut Il2CppString> {
    let ptr = state::helper(GameFunction::FindString);
    if ptr.is_null() {
        return None;
    }
    let f: FindStringFn = unsafe { std::mem::transmute(ptr) };
    let string = unsafe { silent_val(move || f(value.as_ptr() as *const c_char)) };
    string.and_then(|s| (!s.is_null()).then_some(s))
}

pub(crate) unsafe fn find_game_object(value: *mut Il2CppString) -> Option<*mut c_void> {
    let ptr = state::helper(GameFunction::FindGameObject);
    if ptr.is_null() {
        return None;
    }
    let f: FindGameObjectFn = unsafe { std::mem::transmute(ptr) };
    let object = unsafe { silent_val(move || f(value)) };
    object.and_then(|o| (!o.is_null()).then_some(o))
}

pub(crate) unsafe fn set_active(object: *mut c_void, active: bool) -> bool {
    let ptr = state::helper(GameFunction::SetActive);
    if ptr.is_null() {
        return false;
    }
    let f: SetActiveFn = unsafe { std::mem::transmute(ptr) };
    unsafe { silent(move || f(object, active)) }
}

pub(crate) fn has_unity_object_helpers() -> bool {
    !state::helper(GameFunction::FindString).is_null()
        && !state::helper(GameFunction::FindGameObject).is_null()
        && !state::helper(GameFunction::SetActive).is_null()
}
