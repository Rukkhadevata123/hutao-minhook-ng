use std::{
    fmt::{self, Write},
    fs::OpenOptions,
    io::Write as IoWrite,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};
use windows_sys::Win32::{
    Foundation::{HMODULE, MAX_PATH},
    System::LibraryLoader::GetModuleFileNameW,
};

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();
static LOG_LOCK: Mutex<()> = Mutex::new(());

pub fn setup_path(h_module: HMODULE) {
    unsafe {
        let mut path = [0u16; MAX_PATH as usize];
        let len = GetModuleFileNameW(h_module, path.as_mut_ptr(), MAX_PATH);
        if len == 0 {
            return;
        }

        let dll_path = PathBuf::from(String::from_utf16_lossy(&path[..len as usize]));
        if let Some(parent) = dll_path.parent() {
            let _ = LOG_PATH.set(parent.join("hutao_minhook_ng.log"));
        }
    }
}

pub fn enabled() -> bool {
    crate::config::get_config().debug_mode
}

pub fn start_session() {
    if !enabled() {
        return;
    }

    let Some(path) = LOG_PATH.get() else {
        return;
    };

    let Ok(_guard) = LOG_LOCK.lock() else {
        return;
    };

    let _ = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .and_then(|mut file| file.write_all(b"logger: start\n"));
}

pub fn write(args: fmt::Arguments<'_>) {
    let Some(path) = LOG_PATH.get() else {
        return;
    };

    let Ok(_guard) = LOG_LOCK.lock() else {
        return;
    };

    let mut line = String::new();
    let _ = line.write_fmt(args);
    if !line.ends_with('\n') {
        line.push('\n');
    }

    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(line.as_bytes()));
}

macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::logger::enabled() {
            $crate::logger::write(format_args!($($arg)*));
        }
    };
}

pub(crate) use debug;
