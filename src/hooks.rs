//！ Acknowledgements:
//！ - <https://github.com/DGP-Studio/UnlockerIsland>
//！ - <https://github.com/isxlan0/Genshin.Fps.UnlockerIsland>

use crate::config::get_config;
use crate::hutao_seh::try_seh;
use crate::scan_key;
use min_hook_rs::{ALL_HOOKS, create_hook, enable_hook};
use std::ffi::{c_char, c_void};
use std::ptr;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

// IL2CPP Structures
#[repr(C)]
pub struct Il2CppObject {
    pub klass: *mut c_void,
    pub monitor: *mut c_void,
}

#[repr(C)]
pub struct Il2CppString {
    pub object: Il2CppObject,
    pub length: i32,
    pub chars: [u16; 32],
}

// Global Function Pointers (Originals & Helpers)

// Get_FrameCount
static ORIGINAL_GET_FRAME_COUNT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
// Set_FrameCount (Not hooked, just called)
static ORIGINAL_SET_FRAME_COUNT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
// ChangeFOV
static ORIGINAL_CHANGE_FOV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
// DisplayFog
static ORIGINAL_DISPLAY_FOG: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
// Player_Perspective
static ORIGINAL_PLAYER_PERSPECTIVE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
// Touch Screen
static SWITCH_INPUT_DEVICE_TO_TOUCH_SCREEN: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

// Quest Banner
static ORIGINAL_SETUP_QUEST_BANNER: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static FIND_GAME_OBJECT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static SET_ACTIVE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

// Event Camera
static ORIGINAL_EVENT_CAMERA_MOVE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

// Damage Text
static ORIGINAL_SHOW_ONE_DAMAGE_TEXT_EX: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

// Craft Redirect
static FIND_STRING: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CRAFT_ENTRY_PARTNER: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ORIGINAL_CRAFT_ENTRY: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

// Team Anime
static CHECK_CAN_ENTER: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OPEN_TEAM_PAGE_ACCORDINGLY: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ORIGINAL_OPEN_TEAM: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

// Global State
static GAME_UPDATE_INIT: AtomicBool = AtomicBool::new(false);
static TOUCH_SCREEN_INIT: Once = Once::new();
// Flag to request opening the craft menu from the main thread
static REQUEST_OPEN_CRAFT: AtomicBool = AtomicBool::new(false);

// Function Type Definitions

// typedef int(*HookGet_FrameCount_t)();
type GetFrameCountFn = unsafe extern "system" fn() -> i32;

// typedef int(*Set_FrameCount_t)(int value);
type SetFrameCountFn = unsafe extern "system" fn(i32) -> i32;

// typedef int(*HookChangeFOV_t)(__int64 a1, float a2);
type ChangeFovFn = unsafe extern "system" fn(*mut c_void, f32) -> i32;

// typedef void (*SwitchInputDeviceToTouchScreen_t)(void*);
type SwitchInputDeviceToTouchScreenFn = unsafe extern "system" fn(*mut c_void);

// Quest Banner Types
// typedef void (*SetupQuestBanner_t)(void*);
type SetupQuestBannerFn = unsafe extern "system" fn(*mut c_void);
// typedef void* (*FindGameObject_t)(Il2CppString*);
type FindGameObjectFn = unsafe extern "system" fn(*mut Il2CppString) -> *mut c_void;
// typedef void (*SetActive_t)(void*, bool);
type SetActiveFn = unsafe extern "system" fn(*mut c_void, bool);

// Event Camera Types
// typedef bool (*EventCameraMove_t)(void*, void*);
type EventCameraMoveFn = unsafe extern "system" fn(*mut c_void, *mut c_void) -> bool;

// Damage Text Types
// typedef void (*ShowOneDamageTextEx_t)(void*, int, int, int, float, Il2CppString*, void*, void*, int);
type ShowOneDamageTextExFn = unsafe extern "system" fn(
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

// typedef void (*HookDisplayFog_t)(bool);
type DisplayFogFn = unsafe extern "system" fn(bool);

// typedef void* (*HookPlayer_Perspective_t)(void* RCX, float Display, void* R8);
type PlayerPerspectiveFn = unsafe extern "system" fn(*mut c_void, f32, *mut c_void) -> *mut c_void;

// Craft Redirect Types
// typedef Il2CppString* (*FindString_t)(const char*);
type FindStringFn = unsafe extern "system" fn(*const c_char) -> *mut Il2CppString;

// typedef void (*CraftEntry_t)(void*);
type CraftEntryFn = unsafe extern "system" fn(*mut c_void);

// typedef bool (*CraftEntryPartner_t)(Il2CppString*, void*, void*, void*, void*);
type CraftEntryPartnerFn = unsafe extern "system" fn(
    *mut Il2CppString,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
) -> bool;

// Team Anime Types
// typedef bool(*CheckCanEnter_t)();
type CheckCanEnterFn = unsafe extern "system" fn() -> bool;

// typedef void(*OpenTeam_t)();
type OpenTeamFn = unsafe extern "system" fn();

// typedef void(*OpenTeamPageAccordingly_t)(bool);
type OpenTeamPageAccordinglyFn = unsafe extern "system" fn(bool);

// Hook Implementations

// Public helper to set the request flag
pub fn request_open_craft() {
    REQUEST_OPEN_CRAFT.store(true, Ordering::Relaxed);
}

// Internal helper to actually open the menu (must be called from main thread)
// Returns true if successfully dispatched
unsafe fn do_open_craft_menu() -> bool {
    let find_string_ptr = FIND_STRING.load(Ordering::Relaxed);
    let craft_partner_ptr = CRAFT_ENTRY_PARTNER.load(Ordering::Relaxed);

    if !find_string_ptr.is_null() && !craft_partner_ptr.is_null() {
        unsafe {
            let find_string: FindStringFn = std::mem::transmute(find_string_ptr);
            let craft_entry_partner: CraftEntryPartnerFn = std::mem::transmute(craft_partner_ptr);

            // path to the global combine page
            let s = b"SynthesisPage\0";
            let str_obj = find_string(s.as_ptr() as *const c_char);

            if !str_obj.is_null() {
                // Invoke the page opener
                craft_entry_partner(
                    str_obj,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                return true;
            }
        }
    }
    false
}

unsafe extern "system" fn hook_get_frame_count() -> i32 {
    unsafe {
        let original_ptr = ORIGINAL_GET_FRAME_COUNT.load(Ordering::Relaxed);
        if !original_ptr.is_null() {
            let original: GetFrameCountFn = std::mem::transmute(original_ptr);
            let ret = original();
            if ret >= 60 {
                60
            } else if ret >= 45 {
                45
            } else if ret >= 30 {
                30
            } else {
                ret
            }
        } else {
            60
        }
    }
}

unsafe extern "system" fn hook_update_loop(a1: *mut c_void, mut change_fov_value: f32) -> i32 {
    unsafe {
        if !GAME_UPDATE_INIT.load(Ordering::Relaxed) {
            GAME_UPDATE_INIT.store(true, Ordering::Relaxed);
        }

        let config = get_config();

        // Check for craft menu request (Main Thread Execution)
        if REQUEST_OPEN_CRAFT.load(Ordering::Relaxed) {
            REQUEST_OPEN_CRAFT.store(false, Ordering::Relaxed);
            // We don't care about the return value here, just do it
            do_open_craft_menu();
        }

        TOUCH_SCREEN_INIT.call_once(|| {
            if config.use_touch_screen {
                let switch_input_ptr = SWITCH_INPUT_DEVICE_TO_TOUCH_SCREEN.load(Ordering::Relaxed);
                if !switch_input_ptr.is_null() {
                    let switch_input: SwitchInputDeviceToTouchScreenFn =
                        std::mem::transmute(switch_input_ptr);
                    // Wrap in SEH as per island.cpp logic
                    let _ = try_seh(|| {
                        switch_input(ptr::null_mut());
                    });
                }
            }
        });

        if config.enable_fps_override {
            let set_frame_count_ptr = ORIGINAL_SET_FRAME_COUNT.load(Ordering::Relaxed);
            if !set_frame_count_ptr.is_null() {
                let set_frame_count: SetFrameCountFn = std::mem::transmute(set_frame_count_ptr);
                set_frame_count(config.selected_fps);
            }
        }

        let display_fog_ptr = ORIGINAL_DISPLAY_FOG.load(Ordering::Relaxed);
        if !display_fog_ptr.is_null() {
            let display_fog: DisplayFogFn = std::mem::transmute(display_fog_ptr);

            // If enable_display_fog_override is True, it means "Disable Fog" -> pass false
            // If enable_display_fog_override is False, it means "Enable Fog" -> pass true
            display_fog(!config.enable_display_fog_override);
        }

        if change_fov_value > 30.0 && config.enable_fov_override {
            change_fov_value = config.fov_value;
        }

        let original_ptr = ORIGINAL_CHANGE_FOV.load(Ordering::Relaxed);
        if !original_ptr.is_null() {
            let original: ChangeFovFn = std::mem::transmute(original_ptr);
            original(a1, change_fov_value)
        } else {
            0
        }
    }
}

unsafe extern "system" fn hook_player_perspective(
    rcx: *mut c_void,
    mut display: f32,
    r8: *mut c_void,
) -> *mut c_void {
    unsafe {
        let config = get_config();
        if config.enable_perspective_override {
            display = 1.0;
        }

        let original_ptr = ORIGINAL_PLAYER_PERSPECTIVE.load(Ordering::Relaxed);
        if !original_ptr.is_null() {
            let original: PlayerPerspectiveFn = std::mem::transmute(original_ptr);
            original(rcx, display, r8)
        } else {
            ptr::null_mut()
        }
    }
}

unsafe extern "system" fn hook_hide_something(p_this: *mut c_void) {
    unsafe {
        let config = get_config();

        let find_string_ptr = FIND_STRING.load(Ordering::Relaxed);
        let find_game_object_ptr = FIND_GAME_OBJECT.load(Ordering::Relaxed);
        let set_active_ptr = SET_ACTIVE.load(Ordering::Relaxed);

        if !find_string_ptr.is_null()
            && !find_game_object_ptr.is_null()
            && !set_active_ptr.is_null()
        {
            let find_string: FindStringFn = std::mem::transmute(find_string_ptr);
            let find_game_object: FindGameObjectFn = std::mem::transmute(find_game_object_ptr);
            let set_active: SetActiveFn = std::mem::transmute(set_active_ptr);

            // Hide UID Logic
            if config.hide_uid {
                let s = b"/BetaWatermarkCanvas(Clone)/Panel/TxtUID\0";
                let str_obj = find_string(s.as_ptr() as *const c_char);
                if !str_obj.is_null() {
                    let uid_obj = find_game_object(str_obj);
                    if !uid_obj.is_null() {
                        set_active(uid_obj, false);
                    }
                }
            }

            // Hide Quest Banner Logic
            if config.hide_quest_banner {
                let s = b"Canvas/Pages/InLevelMapPage/GrpMap/GrpPointTips/Layout/QuestBanner\0";
                let str_obj = find_string(s.as_ptr() as *const c_char);
                if !str_obj.is_null() {
                    let banner = find_game_object(str_obj);
                    if !banner.is_null() {
                        set_active(banner, false);
                        return;
                    }
                }
            }
        }

        let original_ptr = ORIGINAL_SETUP_QUEST_BANNER.load(Ordering::Relaxed);
        if !original_ptr.is_null() {
            let original: SetupQuestBannerFn = std::mem::transmute(original_ptr);
            original(p_this);
        }
    }
}

unsafe extern "system" fn hook_event_camera_move(p_this: *mut c_void, event: *mut c_void) -> bool {
    unsafe {
        let config = get_config();
        if config.disable_event_camera_move {
            return true;
        }

        let original_ptr = ORIGINAL_EVENT_CAMERA_MOVE.load(Ordering::Relaxed);
        if !original_ptr.is_null() {
            let original: EventCameraMoveFn = std::mem::transmute(original_ptr);
            original(p_this, event)
        } else {
            true // Default return?
        }
    }
}

unsafe extern "system" fn hook_show_one_damage_text_ex(
    p_this: *mut c_void,
    type_: i32,
    damage_type: i32,
    show_type: i32,
    damage: f32,
    show_text: *mut Il2CppString,
    world_pos: *mut c_void,
    attackee: *mut c_void,
    element_reaction_type: i32,
) {
    unsafe {
        let config = get_config();
        if config.disable_show_damage_text {
            return;
        }

        let original_ptr = ORIGINAL_SHOW_ONE_DAMAGE_TEXT_EX.load(Ordering::Relaxed);
        if !original_ptr.is_null() {
            let original: ShowOneDamageTextExFn = std::mem::transmute(original_ptr);
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
            );
        }
    }
}

unsafe extern "system" fn hook_craft_entry(p_this: *mut c_void) {
    unsafe {
        let config = get_config();

        // If redirect is enabled AND we successfully opened the menu via our helper
        if config.enable_redirect_craft_override && do_open_craft_menu() {
            // Return early, skipping the original tedious dialog
            return;
        }

        let original_ptr = ORIGINAL_CRAFT_ENTRY.load(Ordering::Relaxed);
        if !original_ptr.is_null() {
            let original: CraftEntryFn = std::mem::transmute(original_ptr);
            original(p_this);
        }
    }
}

unsafe extern "system" fn hook_open_team() {
    unsafe {
        let config = get_config();
        let check_can_enter_ptr = CHECK_CAN_ENTER.load(Ordering::Relaxed);

        if config.enable_remove_team_anim && !check_can_enter_ptr.is_null() {
            let check_can_enter: CheckCanEnterFn = std::mem::transmute(check_can_enter_ptr);
            if check_can_enter() {
                let open_team_page_ptr = OPEN_TEAM_PAGE_ACCORDINGLY.load(Ordering::Relaxed);
                if !open_team_page_ptr.is_null() {
                    let open_team_page: OpenTeamPageAccordinglyFn =
                        std::mem::transmute(open_team_page_ptr);
                    open_team_page(false);
                    return;
                }
            }
        }

        let original_ptr = ORIGINAL_OPEN_TEAM.load(Ordering::Relaxed);
        if !original_ptr.is_null() {
            let original: OpenTeamFn = std::mem::transmute(original_ptr);
            original();
        }
    }
}

// Initialization

pub fn init_hooks() -> bool {
    if min_hook_rs::initialize().is_err() {
        return false;
    }

    // Get_FrameCount
    scan_key!(
        get_frame_count_addr,
        "E8 ? ? ? ? 85 C0 7E 0E E8 ? ? ? ? 0F 57 C0 F3 0F 2A C0 EB 08",
        1
    );
    if !get_frame_count_addr.is_null()
        && let Ok(trampoline) =
            create_hook(get_frame_count_addr, hook_get_frame_count as *mut c_void)
    {
        ORIGINAL_GET_FRAME_COUNT.store(trampoline, Ordering::Relaxed);
    }

    // Set_FrameCount (No Hook, just store address)
    scan_key!(
        set_frame_count_addr,
        "E8 ? ? ? ? E8 ? ? ? ? 83 F8 1F 0F 9C 05 ? ? ? ? 48 8B 05",
        1
    );
    if !set_frame_count_addr.is_null() {
        ORIGINAL_SET_FRAME_COUNT.store(set_frame_count_addr, Ordering::Relaxed);
    }

    // ChangeFOV
    scan_key!(
        change_fov_addr,
        "40 53 48 83 EC 60 0F 29 74 24 ? 48 8B D9 0F 28 F1 E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 48 8B C8 "
    );
    if !change_fov_addr.is_null()
        && let Ok(trampoline) = create_hook(change_fov_addr, hook_update_loop as *mut c_void)
    {
        ORIGINAL_CHANGE_FOV.store(trampoline, Ordering::Relaxed);
    }

    // SwitchInputDeviceToTouchScreen
    scan_key!(
        switch_input_device_addr,
        "56 57 48 83 EC ? 48 89 CE 80 3D ? ? ? ? 00 48 8B 05 ? ? ? ? 0F 85 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 48 8B 15 ? ? ? ? E8 ? ? ? ? 48 89 C7 48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 31 D2"
    );
    if !switch_input_device_addr.is_null() {
        SWITCH_INPUT_DEVICE_TO_TOUCH_SCREEN.store(switch_input_device_addr, Ordering::Relaxed);
    }

    // SetupQuestBanner
    scan_key!(
        setup_quest_banner_addr,
        "41 57 41 56 56 57 55 53 48 81 EC ? ? ? ? 0F 29 BC 24 ? ? ? ? 0F 29 B4 24 ? ? ? ? 48 89 CE 80 3D ? ? ? ? 00 0F 85 ? ? ? ? 48 8B 96"
    );
    if !setup_quest_banner_addr.is_null()
        && let Ok(trampoline) =
            create_hook(setup_quest_banner_addr, hook_hide_something as *mut c_void)
    {
        ORIGINAL_SETUP_QUEST_BANNER.store(trampoline, Ordering::Relaxed);
    }

    // FindGameObject (Resolve 1 for E9 jump)
    scan_key!(
        find_game_object_addr,
        "E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? 48 83 EC ? C7 44 24 ? 00 00 00 00 48 8D 54 24",
        1
    );
    if !find_game_object_addr.is_null() {
        FIND_GAME_OBJECT.store(find_game_object_addr, Ordering::Relaxed);
    }

    // SetActive (Resolve 1 for E9 jump)
    scan_key!(
        set_active_addr,
        "E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? 45 31 C9",
        1
    );
    if !set_active_addr.is_null() {
        SET_ACTIVE.store(set_active_addr, Ordering::Relaxed);
    }

    // EventCameraMove
    scan_key!(
        event_camera_move_addr,
        "41 57 41 56 56 57 55 53 48 83 EC ? 48 89 D7 49 89 CE 80 3D ? ? ? ? 00 0F 85 ? ? ? ? 80 3D ? ? ? ? 00"
    );
    if !event_camera_move_addr.is_null()
        && let Ok(trampoline) = create_hook(
            event_camera_move_addr,
            hook_event_camera_move as *mut c_void,
        )
    {
        ORIGINAL_EVENT_CAMERA_MOVE.store(trampoline, Ordering::Relaxed);
    }

    // ShowOneDamageTextEx
    scan_key!(
        show_one_damage_text_ex_addr,
        "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 44 0F 29 9C 24 ? ? ? ? 44 0F 29 94 24 ? ? ? ? 44 0F 29 8C 24 ? ? ? ? 44 0F 29 84 24 ? ? ? ? 0F 29 BC 24 ? ? ? ? 0F 29 B4 24 ? ? ? ? 44 89 CF 45 89 C4"
    );
    if !show_one_damage_text_ex_addr.is_null()
        && let Ok(trampoline) = create_hook(
            show_one_damage_text_ex_addr,
            hook_show_one_damage_text_ex as *mut c_void,
        )
    {
        ORIGINAL_SHOW_ONE_DAMAGE_TEXT_EX.store(trampoline, Ordering::Relaxed);
    }

    // DisplayFog
    scan_key!(
        display_fog_addr,
        "E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? C3 66 66 66 66 66 66 2E 0F 1F 84 00 ? ? ? ? 48 8B 41 ? C3 66 66 2E 0F 1F 84 00 ? ? ? ? 48 8B 41"
    );
    if !display_fog_addr.is_null() {
        ORIGINAL_DISPLAY_FOG.store(display_fog_addr, Ordering::Relaxed);
    }

    // Player_Perspective
    scan_key!(
        player_perspective_addr,
        "E8 ? ? ? ? 48 8B BE ? ? ? ? 80 3D ? ? ? ? ? 0F 85 ? ? ? ? 80 BE ? ? ? ? ? 74 11",
        1
    );
    if !player_perspective_addr.is_null()
        && let Ok(trampoline) = create_hook(
            player_perspective_addr,
            hook_player_perspective as *mut c_void,
        )
    {
        ORIGINAL_PLAYER_PERSPECTIVE.store(trampoline, Ordering::Relaxed);
    }

    // Craft Redirect
    scan_key!(
        find_string_addr,
        "56 48 83 ec 20 48 89 ce e8 ? ? ? ? 48 89 f1 89 c2 48 83 c4 20 5e e9 ? ? ? ? cc cc cc cc"
    );
    if !find_string_addr.is_null() {
        FIND_STRING.store(find_string_addr, Ordering::Relaxed);
    }

    scan_key!(
        craft_entry_partner_addr,
        "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 4D 89 ? 4C 89 C6 49 89 D4 49 89 CE"
    );
    if !craft_entry_partner_addr.is_null() {
        CRAFT_ENTRY_PARTNER.store(craft_entry_partner_addr, Ordering::Relaxed);
    }

    scan_key!(
        craft_entry_addr,
        "41 56 56 57 53 48 83 EC 58 49 89 CE 80 3D ? ? ? ? 00 0F 84 ? ? ? ? 80 3D ? ? ? ? 00 48 8B 0D ? ? ? ? 0F 85"
    );
    if !craft_entry_addr.is_null()
        && let Ok(trampoline) = create_hook(craft_entry_addr, hook_craft_entry as *mut c_void)
    {
        ORIGINAL_CRAFT_ENTRY.store(trampoline, Ordering::Relaxed);
    }

    // Team Anime
    scan_key!(
        check_can_enter_addr,
        "56 48 81 ec 80 00 00 00 80 3d ? ? ? ? 00 0f 84 ? ? ? ? 80 3d ? ? ? ? 00"
    );
    if !check_can_enter_addr.is_null() {
        CHECK_CAN_ENTER.store(check_can_enter_addr, Ordering::Relaxed);
    }

    scan_key!(
        open_team_page_addr,
        "56 57 53 48 83 ec 20 89 cb 80 3d ? ? ? ? 00 74 7a 80 3d ? ? ? ? 00 48 8b 05"
    );
    if !open_team_page_addr.is_null() {
        OPEN_TEAM_PAGE_ACCORDINGLY.store(open_team_page_addr, Ordering::Relaxed);
    }

    scan_key!(
        open_team_addr,
        "48 83 EC ? 80 3D ? ? ? ? 00 75 ? 48 8B 0D ? ? ? ? 80 B9 ? ? ? ? 00 0F 84 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 84 C0 75"
    );
    if !open_team_addr.is_null()
        && let Ok(trampoline) = create_hook(open_team_addr, hook_open_team as *mut c_void)
    {
        ORIGINAL_OPEN_TEAM.store(trampoline, Ordering::Relaxed);
    }

    // Enable all hooks
    enable_hook(ALL_HOOKS).is_ok()
}

pub fn is_game_update_init() -> bool {
    GAME_UPDATE_INIT.load(Ordering::Relaxed)
}
