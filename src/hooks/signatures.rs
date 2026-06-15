use crate::scanner;
use std::ffi::c_void;
use std::ptr;

struct Signature {
    pattern: &'static str,
    resolve_times: u8,
}

impl Signature {
    fn resolve(
        &self,
        scanner: &scanner::ScanSession,
        function: GameFunction,
    ) -> Option<*mut c_void> {
        let cache_key = function.cache_key();
        scanner.resolve_cached(&cache_key, self.pattern, self.resolve_times)
    }
}

pub(super) struct ResolvedAddresses {
    entries: [*mut c_void; GameFunction::COUNT],
}

impl ResolvedAddresses {
    fn empty() -> Self {
        Self {
            entries: [ptr::null_mut(); GameFunction::COUNT],
        }
    }

    pub(super) fn get(&self, function: GameFunction) -> Option<*mut c_void> {
        let addr = self.entries[function.as_index()];
        (!addr.is_null()).then_some(addr)
    }

    fn set(&mut self, function: GameFunction, addr: *mut c_void) {
        self.entries[function.as_index()] = addr;
    }
}

macro_rules! game_functions {
    ($($key:ident => ($pattern:literal $(, $resolve_times:literal)? $(,)?)),+ $(,)?) => {
        #[repr(usize)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum GameFunction {
            $($key),+
        }

        impl GameFunction {
            pub const COUNT: usize = [$(Self::$key),+].len();

            pub const fn as_index(self) -> usize {
                self as usize
            }

            fn cache_key(self) -> String {
                let name = match self {
                    $(Self::$key => stringify!($key),)+
                };

                let mut key = String::new();
                for (index, ch) in name.chars().enumerate() {
                    if ch.is_ascii_uppercase() {
                        if index > 0 {
                            key.push('_');
                        }
                        key.push(ch.to_ascii_lowercase());
                    } else {
                        key.push(ch);
                    }
                }
                key.push_str("_addr");
                key
            }
        }

        const SIGNATURES: [Signature; GameFunction::COUNT] = [
            $(
                Signature {
                    pattern: $pattern,
                    resolve_times: game_functions!(@resolve_times $($resolve_times)?),
                },
            )+
        ];
    };
    (@resolve_times) => {
        0
    };
    (@resolve_times $resolve_times:literal) => {
        $resolve_times
    };
}

game_functions! {
    GetFrameCount => (
        "E8 ? ? ? ? 85 C0 7E 0E E8 ? ? ? ? 0F 57 C0 F3 0F 2A C0 EB 08",
        1,
    ),
    SetFrameCount => (
        "E8 ? ? ? ? E8 ? ? ? ? 83 F8 1F 0F 9C 05 ? ? ? ? 48 8B 05",
        1,
    ),
    ChangeFov => (
        "40 53 48 83 EC 60 0F 29 74 24 ? 48 8B D9 0F 28 F1 E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 48 8B C8 ",
    ),
    SwitchInputDevice => (
        "56 57 48 83 EC ? 48 89 CE 80 3D ? ? ? ? 00 48 8B 05 ? ? ? ? 0F 85 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 48 8B 15 ? ? ? ? E8 ? ? ? ? 48 89 C7 48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 31 D2",
    ),
    SetupQuestBanner => (
        "41 57 41 56 56 57 55 53 48 81 EC ? ? ? ? 0F 29 BC 24 ? ? ? ? 0F 29 B4 24 ? ? ? ? 48 89 CE 80 3D ? ? ? ? 00 0F 85",
    ),
    FindGameObject => (
        "E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? 48 83 EC ? C7 44 24 ? 00 00 00 00 48 8D 54 24",
        1,
    ),
    SetActive => (
        "E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? 45 31 C9",
        1,
    ),
    EventCameraMove => (
        "41 57 41 56 56 57 55 53 48 83 EC ? 48 89 D7 48 89 CE 80 3D ? ? ? ? ? 0F 85 ? ? ? ? 48 89 F1 E8",
    ),
    ShowDamageText => (
        "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 44 0F 29 9C 24 ? ? ? ? 44 0F 29 94 24 ? ? ? ? 44 0F 29 8C 24 ? ? ? ? 44 0F 29 84 24 ? ? ? ? 0F 29 BC 24 ? ? ? ? 0F 29 B4 24 ? ? ? ? 44 89 CF",
    ),
    DisplayFog => (
        "E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? C3 66 66 66 66 66 66 2E 0F 1F 84 00 ? ? ? ? 48 8B 41 ? C3 66 66 2E 0F 1F 84 00 ? ? ? ? 48 8B 41 ? C3 66 66 2E 0F 1F 84 00 ? ? ? ? 8B 41 ?",
    ),
    PlayerPerspective => (
        "E8 ? ? ? ? 48 8B BE ? ? ? ? 80 3D ? ? ? ? ? 0F 85 ? ? ? ? 80 BE ? ? ? ? ? 74 11",
        1,
    ),
    FindString => (
        "56 48 83 ec 20 48 89 ce e8 ? ? ? ? 48 89 f1 89 c2 48 83 c4 20 5e e9 ? ? ? ? cc cc cc cc",
    ),
    CraftEntryPartner => (
        "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 4D 89 ? 4C 89 C6 49 89 D4 49 89 CE",
    ),
    CraftEntry => (
        "41 56 56 57 53 48 83 EC 58 49 89 CE 80 3D ? ? ? ? 00 0F 84 ? ? ? ? 80 3D ? ? ? ? 00 48 8B 0D ? ? ? ? 0F 85",
    ),
    CheckCanOpenMap => (
        "E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? 48 8B 45 ? 48 85 C0 74 ? 41 8B 17 4C 8B 40 ? 48 8B 48 ? FF 50 ? 84 C0 0F 84 ? ? ? ?",
        1,
    ),
    CheckCanEnter => (
        "56 48 81 ec 80 00 00 00 80 3d ? ? ? ? 00 0f 84 ? ? ? ? 80 3d ? ? ? ? 00",
    ),
    OpenTeamPage => (
        "56 57 53 48 83 ec 20 89 cb 80 3d ? ? ? ? 00 74 7a 80 3d ? ? ? ? 00 48 8b 05",
    ),
    OpenTeam => (
        "48 83 EC ? 80 3D ? ? ? ? 00 75 ? 48 8B 0D ? ? ? ? 80 B9 ? ? ? ? 00 0F 84 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 84 C0 75",
    ),
}

pub(super) fn resolve_all(functions: &[GameFunction]) -> ResolvedAddresses {
    let scanner = scanner::ScanSession::new();
    let mut addresses = ResolvedAddresses::empty();

    for function in functions {
        if let Some(addr) = SIGNATURES[function.as_index()].resolve(&scanner, *function) {
            addresses.set(*function, addr);
        }
    }

    addresses
}
