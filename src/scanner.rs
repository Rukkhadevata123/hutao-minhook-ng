use crate::hutao_seh::try_seh;
use std::collections::HashSet;
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

struct RegionInfo {
    base: *mut c_void,
    size: usize,
}

pub struct ScanSession {
    regions: Vec<RegionInfo>,
}

impl ScanSession {
    pub fn new() -> Self {
        Self {
            regions: get_memory_regions(),
        }
    }

    pub fn resolve_cached(
        &self,
        key: &str,
        pattern: &str,
        resolve_times: u8,
    ) -> Option<*mut c_void> {
        let cfg_addrs = crate::config::load_offsets(key);
        if !cfg_addrs.is_empty() {
            return Some(cfg_addrs[0] as *mut c_void);
        }

        let matches = self.scan_limit(pattern, 10);
        let mut resolved_vec: Vec<usize> = Vec::new();
        let mut seen: HashSet<usize> = HashSet::new();

        for m in matches.iter() {
            let mut addr = *m;
            if addr.is_null() {
                continue;
            }

            for _ in 0..resolve_times {
                addr = resolve_relative_address(addr, 1, 5);
                if addr.is_null() {
                    break;
                }
            }
            if addr.is_null() {
                continue;
            }

            let addr_usize = addr as usize;
            if !seen.insert(addr_usize) {
                continue;
            }

            resolved_vec.push(addr_usize);
            if resolved_vec.len() >= 10 {
                break;
            }
        }

        if !resolved_vec.is_empty() {
            let _ = crate::config::write_offsets(key, &resolved_vec);
            return Some(resolved_vec[0] as *mut c_void);
        }

        None
    }

    fn scan_limit(&self, pattern: &str, limit: usize) -> Vec<*mut c_void> {
        let parsed_pattern = parse_pattern(pattern);
        let mut all = Vec::new();

        for region in &self.regions {
            let remaining = limit.saturating_sub(all.len());
            if remaining == 0 {
                break;
            }

            all.extend(scan_region(
                region.base,
                region.size,
                &parsed_pattern,
                remaining,
            ));
        }

        all
    }
}

fn is_readable_or_executable(protect: u32) -> bool {
    protect == PAGE_EXECUTE_READ
        || protect == PAGE_EXECUTE_READWRITE
        || protect == PAGE_EXECUTE_WRITECOPY
        || protect == PAGE_EXECUTE
        || protect == PAGE_READONLY
        || protect == PAGE_READWRITE
        || protect == PAGE_WRITECOPY
}

fn get_main_module_range() -> (usize, usize) {
    unsafe {
        let base = GetModuleHandleW(ptr::null()) as usize;
        if base == 0 {
            return (0, 0);
        }
        let dos_header = base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            // Not MZ
            return (0, 0);
        }
        let nt_headers = (base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).Signature != 0x00004550 {
            // Not PE
            return (0, 0);
        }
        let size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
        (base, size)
    }
}

fn get_memory_regions() -> Vec<RegionInfo> {
    let mut regions = Vec::new();
    unsafe {
        let (module_base, module_size) = get_main_module_range();
        if module_base == 0 || module_size == 0 {
            return regions;
        }

        let mut start = module_base;
        let end = module_base + module_size;

        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

        while start < end {
            if VirtualQuery(
                start as *const c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            if mbi.State == MEM_COMMIT && is_readable_or_executable(mbi.Protect) {
                regions.push(RegionInfo {
                    base: mbi.BaseAddress,
                    size: mbi.RegionSize,
                });
            }

            start += mbi.RegionSize;
        }
    }
    regions
}

struct Pattern {
    bytes: Vec<u8>,
    mask: Vec<u8>,
    anchor_offset: Option<usize>,
}

fn parse_pattern(pattern: &str) -> Pattern {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    let mut anchor_offset = None;

    for (i, s) in pattern.split_whitespace().enumerate() {
        if s == "?" || s == "??" {
            bytes.push(0);
            mask.push(0); // 0x00 means wildcard
        } else {
            let b = u8::from_str_radix(s, 16).unwrap_or(0);
            bytes.push(b);
            mask.push(0xFF); // 0xFF means exact match

            if anchor_offset.is_none() {
                anchor_offset = Some(i);
            }
        }
    }

    Pattern {
        bytes,
        mask,
        anchor_offset,
    }
}

fn scan_region(
    region_base: *mut c_void,
    region_size: usize,
    pattern: &Pattern,
    limit: usize,
) -> Vec<*mut c_void> {
    let pattern_len = pattern.bytes.len();
    if limit == 0 || region_size < pattern_len {
        return Vec::new();
    }

    let result = try_seh(|| unsafe {
        let mut results: Vec<*mut c_void> = Vec::new();
        let base_ptr = region_base as *const u8;
        let region_slice = std::slice::from_raw_parts(base_ptr, region_size);

        match pattern.anchor_offset {
            Some(anchor_idx) => {
                let anchor_byte = pattern.bytes[anchor_idx];
                let mut offset = 0;

                while let Some(pos) = region_slice[offset..]
                    .iter()
                    .position(|&b| b == anchor_byte)
                {
                    let current_match_pos = offset + pos;

                    if current_match_pos >= anchor_idx {
                        let start_candidate = current_match_pos - anchor_idx;

                        if start_candidate + pattern_len <= region_size {
                            let mut is_match = true;
                            for i in 0..pattern_len {
                                if i == anchor_idx {
                                    continue;
                                }

                                let mem_byte = *base_ptr.add(start_candidate + i);
                                let pat_byte = pattern.bytes[i];
                                let mask_byte = pattern.mask[i];

                                if (mem_byte & mask_byte) != pat_byte {
                                    is_match = false;
                                    break;
                                }
                            }

                            if is_match {
                                results.push(base_ptr.add(start_candidate) as *mut c_void);
                                if results.len() >= limit {
                                    return results;
                                }
                            }
                        }
                    }

                    offset = current_match_pos + 1;
                    if offset >= region_size {
                        break;
                    }
                }
            }
            None => {
                if pattern_len <= region_size {
                    for i in 0..=(region_size - pattern_len) {
                        results.push(base_ptr.add(i) as *mut c_void);
                        if results.len() >= limit {
                            return results;
                        }
                    }
                }
            }
        }
        results
    });

    result.unwrap_or_else(|_| Vec::new())
}

pub fn resolve_relative_address(
    instruction_addr: *mut c_void,
    offset: usize,
    instruction_size: usize,
) -> *mut c_void {
    if instruction_addr.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let instr_addr_val = instruction_addr as usize;
        let relative_offset_ptr = (instr_addr_val + offset) as *const i32;

        let relative_offset = *relative_offset_ptr;

        let target_addr =
            (instr_addr_val + instruction_size).wrapping_add(relative_offset as usize);

        target_addr as *mut c_void
    }
}
