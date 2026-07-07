use crate::game::il2cpp::Il2CppString;
use std::ffi::{c_char, c_void};

pub type GetFrameCountFn = unsafe extern "system" fn() -> i32;
pub type SetFrameCountFn = unsafe extern "system" fn(i32) -> i32;
pub type ChangeFovFn = unsafe extern "system" fn(*mut c_void, f32) -> i32;
pub type CameraBrainFlushFn = unsafe extern "system" fn(*mut c_void) -> i64;
pub type SwitchInputDeviceToTouchScreenFn = unsafe extern "system" fn(*mut c_void);
pub type SetupQuestBannerFn = unsafe extern "system" fn(*mut c_void);
pub type FindGameObjectFn = unsafe extern "system" fn(*mut Il2CppString) -> *mut c_void;
pub type SetActiveFn = unsafe extern "system" fn(*mut c_void, bool);
pub type EventCameraMoveFn = unsafe extern "system" fn(*mut c_void, *mut c_void) -> bool;
pub type ShowDamageTextFn = unsafe extern "system" fn(
    *mut c_void,
    i32,
    i32,
    i32,
    f32,
    *mut Il2CppString,
    *mut c_void,
    *mut c_void,
    i32,
);
pub type DisplayFogFn = unsafe extern "system" fn(bool);
pub type PlayerPerspectiveFn = unsafe extern "system" fn(*mut c_void, bool);
pub type FindStringFn = unsafe extern "system" fn(*const c_char) -> *mut Il2CppString;
pub type CraftEntryFn = unsafe extern "system" fn(*mut c_void);
pub type CraftEntryPartnerFn = unsafe extern "system" fn(
    *mut Il2CppString,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
) -> bool;
pub type CheckCanOpenMapFn = unsafe extern "system" fn(*mut c_void) -> bool;
pub type CheckCanEnterFn = unsafe extern "system" fn() -> bool;
pub type OpenTeamFn = unsafe extern "system" fn();
pub type OpenTeamPageAccordinglyFn = unsafe extern "system" fn(bool);
