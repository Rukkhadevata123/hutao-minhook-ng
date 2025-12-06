use crate::config::get_config;
use crate::scanner::{resolve_relative_address, scan};
use min_hook_rs::{ALL_HOOKS, create_hook, enable_hook};
use std::ffi::{c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

// =============================================================================================
// IL2CPP Structures
// =============================================================================================

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

// =============================================================================================
// Global Function Pointers (Originals & Helpers)
// =============================================================================================

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

// =============================================================================================
// Function Type Definitions
// =============================================================================================

// typedef int(*HookGet_FrameCount_t)();
type GetFrameCountFn = unsafe extern "system" fn() -> i32;

// typedef int(*Set_FrameCount_t)(int value);
type SetFrameCountFn = unsafe extern "system" fn(i32) -> i32;

// typedef int(*HookChangeFOV_t)(__int64 a1, float a2);
type ChangeFovFn = unsafe extern "system" fn(*mut c_void, f32) -> i32;

// typedef int(*HookDisplayFog_t)(__int64 a1, __int64 a2);
type DisplayFogFn = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;

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

// =============================================================================================
// Hook Implementations
// =============================================================================================

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

unsafe extern "system" fn hook_change_fps_and_fov(
    a1: *mut c_void,
    mut change_fov_value: f32,
) -> i32 {
    unsafe {
        if !GAME_UPDATE_INIT.load(Ordering::Relaxed) {
            GAME_UPDATE_INIT.store(true, Ordering::Relaxed);
        }

        let config = get_config();

        if config.enable_fps_override {
            let set_frame_count_ptr = ORIGINAL_SET_FRAME_COUNT.load(Ordering::Relaxed);
            if !set_frame_count_ptr.is_null() {
                let set_frame_count: SetFrameCountFn = std::mem::transmute(set_frame_count_ptr);
                set_frame_count(config.selected_fps);
            }
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

// Fake Fog Struct for alignment (64 bytes)
#[repr(C, align(16))]
struct FakeFogStruct([u8; 64]);
static mut FAKE_FOG_STRUCT: FakeFogStruct = FakeFogStruct([0; 64]);

unsafe extern "system" fn hook_display_fog(a1: *mut c_void, a2: *mut c_void) -> i32 {
    unsafe {
        let config = get_config();

        let should_disable_fog = config.enable_display_fog_override;

        if should_disable_fog && !a2.is_null() {
            // Use addr_of_mut to get a stable pointer to FAKE_FOG_STRUCT
            let fake_fog_ptr = ptr::addr_of_mut!(FAKE_FOG_STRUCT);
            // Because the struct is #[repr(C)] and has only one field, casting to a u8 pointer is safe
            let buffer_ptr = fake_fog_ptr as *mut u8;

            // Copy memory from a2 to FAKE_FOG_STRUCT
            ptr::copy_nonoverlapping(a2 as *const u8, buffer_ptr, 64);
            // Set first byte to 0
            *buffer_ptr = 0;

            let original_ptr = ORIGINAL_DISPLAY_FOG.load(Ordering::Relaxed);
            if !original_ptr.is_null() {
                let original: DisplayFogFn = std::mem::transmute(original_ptr);
                // Directly pass the raw pointer
                return original(a1, fake_fog_ptr as *mut c_void);
            }
        }

        let original_ptr = ORIGINAL_DISPLAY_FOG.load(Ordering::Relaxed);
        if !original_ptr.is_null() {
            let original: DisplayFogFn = std::mem::transmute(original_ptr);
            original(a1, a2)
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

unsafe extern "system" fn hook_craft_entry(p_this: *mut c_void) {
    unsafe {
        let config = get_config();
        let find_string_ptr = FIND_STRING.load(Ordering::Relaxed);
        let craft_entry_partner_ptr = CRAFT_ENTRY_PARTNER.load(Ordering::Relaxed);

        if config.enable_redirect_craft_override
            && !find_string_ptr.is_null()
            && !craft_entry_partner_ptr.is_null()
        {
            let find_string: FindStringFn = std::mem::transmute(find_string_ptr);
            let craft_entry_partner: CraftEntryPartnerFn =
                std::mem::transmute(craft_entry_partner_ptr);

            // "SynthesisPage" null-terminated string
            let s = b"SynthesisPage\0";
            let str_obj = find_string(s.as_ptr() as *const c_char);
            if !str_obj.is_null() {
                craft_entry_partner(
                    str_obj,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                return;
            }
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

// =============================================================================================
// Initialization
// =============================================================================================

pub fn init_hooks() -> bool {
    if min_hook_rs::initialize().is_err() {
        return false;
    }

    // New: Add base address
    let base = unsafe { GetModuleHandleW(ptr::null()) } as usize;

    // 2. Get_FrameCount
    let mut get_frame_count_addr =
        scan("E8 ? ? ? ? 85 C0 7E 0E E8 ? ? ? ? 0F 57 C0 F3 0F 2A C0 EB 08");
    get_frame_count_addr = resolve_relative_address(get_frame_count_addr, 1, 5);
    get_frame_count_addr = resolve_relative_address(get_frame_count_addr, 1, 5);
    if !get_frame_count_addr.is_null()
        && let Ok(trampoline) =
            create_hook(get_frame_count_addr, hook_get_frame_count as *mut c_void)
    {
        ORIGINAL_GET_FRAME_COUNT.store(trampoline, Ordering::Relaxed);
    }

    // 3. Set_FrameCount (No Hook, just store address)
    let mut set_frame_count_addr = scan("E8 ? ? ? ? E8 ? ? ? ? 83 F8 1F 0F 9C 05 ? ? ? ? 48 8B 05");
    set_frame_count_addr = resolve_relative_address(set_frame_count_addr, 1, 5);
    set_frame_count_addr = resolve_relative_address(set_frame_count_addr, 1, 5);
    if !set_frame_count_addr.is_null() {
        ORIGINAL_SET_FRAME_COUNT.store(set_frame_count_addr, Ordering::Relaxed);
    }

    // 4. ChangeFOV
    let change_fov_addr = scan(
        "40 53 48 83 EC 60 0F 29 74 24 ? 48 8B D9 0F 28 F1 E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 48 8B C8 ",
    );
    if !change_fov_addr.is_null()
        && let Ok(trampoline) = create_hook(change_fov_addr, hook_change_fps_and_fov as *mut c_void)
    {
        ORIGINAL_CHANGE_FOV.store(trampoline, Ordering::Relaxed);
    }

    // 5. DisplayFog
    let display_fog_addr = scan(
        "0F B6 02 88 01 8B 42 04 89 41 04 F3 0F 10 52 ? F3 0F 10 4A ? F3 0F 10 42 ? 8B 42 08 ",
    );
    if !display_fog_addr.is_null()
        && let Ok(trampoline) = create_hook(display_fog_addr, hook_display_fog as *mut c_void)
    {
        ORIGINAL_DISPLAY_FOG.store(trampoline, Ordering::Relaxed);
    }

    // 6. Player_Perspective
    let mut player_perspective_addr =
        scan("E8 ? ? ? ? 48 8B BE ? ? ? ? 80 3D ? ? ? ? ? 0F 85 ? ? ? ? 80 BE ? ? ? ? ? 74 11");
    player_perspective_addr = resolve_relative_address(player_perspective_addr, 1, 5);
    if !player_perspective_addr.is_null()
        && let Ok(trampoline) = create_hook(
            player_perspective_addr,
            hook_player_perspective as *mut c_void,
        )
    {
        ORIGINAL_PLAYER_PERSPECTIVE.store(trampoline, Ordering::Relaxed);
    }

    // 7. Craft Redirect
    let find_string_addr = scan(
        "56 48 83 ec 20 48 89 ce e8 ? ? ? ? 48 89 f1 89 c2 48 83 c4 20 5e e9 ? ? ? ? cc cc cc cc",
    );
    if !find_string_addr.is_null() {
        FIND_STRING.store(find_string_addr, Ordering::Relaxed);
    }

    let craft_entry_partner_addr = scan(
        "41 57 41 56 41 55 41 54 56 57 55 53 48 81 ec ? ? ? ? 4d 89 cd 4c 89 c6 49 89 d4 49 89 ce 4c 8b bc 24",
    );
    if !craft_entry_partner_addr.is_null() {
        CRAFT_ENTRY_PARTNER.store(craft_entry_partner_addr, Ordering::Relaxed);
    }

    let craft_entry_addr = scan(
        "41 56 56 57 53 48 83 EC 58 49 89 CE 80 3D ? ? ? ? 00 0F 84 ? ? ? ? 80 3D ? ? ? ? 00 48 8B 0D ? ? ? ? 0F 85",
    );
    if !craft_entry_addr.is_null()
        && let Ok(trampoline) = create_hook(craft_entry_addr, hook_craft_entry as *mut c_void)
    {
        ORIGINAL_CRAFT_ENTRY.store(trampoline, Ordering::Relaxed);
    }

    // 8. Team Anime
    let check_can_enter_addr =
        scan("56 48 81 ec 80 00 00 00 80 3d ? ? ? ? 00 0f 84 ? ? ? ? 80 3d ? ? ? ? 00");
    if !check_can_enter_addr.is_null() {
        CHECK_CAN_ENTER.store(check_can_enter_addr, Ordering::Relaxed);
    }

    let open_team_page_addr =
        scan("56 57 53 48 83 ec 20 89 cb 80 3d ? ? ? ? 00 74 7a 80 3d ? ? ? ? 00 48 8b 05");
    if !open_team_page_addr.is_null() {
        OPEN_TEAM_PAGE_ACCORDINGLY.store(open_team_page_addr, Ordering::Relaxed);
    }

    // let open_team_addr = scan(
    //     "48 83 ec 28 80 3d ?? ?? ?? ?? 00 75 ?? 48 8b 0d ?? ?? ?? ?? 80 b9 ?? ?? ?? ?? 00 74 ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 ?? 48 83 c4 28 c3 48 8b 05 ?? ?? ?? ?? 48 8b 80 ?? ?? ?? ?? 48 8b 88 ?? ?? ?? ?? 48 85 c9 0f 84 ?? ?? ?? ?? 48 83 c4 28 e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 75 ?? 48 8b 05",
    // );
    let open_team_addr = (base + 0xb8dcfa0) as *mut c_void;
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
