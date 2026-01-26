
use crate::elf_sectionheaders::{Elf32_Addr, Elf64_Addr};

pub struct Elf32_Dyn {
    pub d_tag: i32,
    pub d_val: u32,
}

pub struct Elf64_Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

fn get_dtag_name(tag: i64) -> String {
    match tag {
        0 => "DT_NULL".to_string(),
        1 => "DT_NEEDED".to_string(),
        2 => "DT_PLTRELSZ".to_string(),
        3 => "DT_PLTGOT".to_string(),
        4 => "DT_HASH".to_string(),
        5 => "DT_STRTAB".to_string(),
        6 => "DT_SYMTAB".to_string(),
        7 => "DT_RELA".to_string(),
        8 => "DT_RELASZ".to_string(),
        9 => "DT_RELAENT".to_string(),
        10 => "DT_STRSZ".to_string(),
        11 => "DT_SYMENT".to_string(),
        12 => "DT_INIT".to_string(),
        13 => "DT_FINI".to_string(),
        14 => "DT_SONAME".to_string(),
        15 => "DT_RPATH".to_string(),
        16 => "DT_SYMBOLIC".to_string(),
        17 => "DT_REL".to_string(),
        18 => "DT_RELSZ".to_string(),
        19 => "DT_RELENT".to_string(),
        20 => "DT_PLTREL".to_string(),
        21 => "DT_DEBUG".to_string(),
        22 => "DT_TEXTREL".to_string(),
        23 => "DT_JMPREL".to_string(),
        24 => "DT_BIND_NOW".to_string(),
        25 => "DT_INIT_ARRAY".to_string(),
        26 => "DT_FINI_ARRAY".to_string(),
        27 => "DT_INIT_ARRAYSZ".to_string(),
        28 => "DT_FINI_ARRAYSZ".to_string(),
        29 => "DT_RUNPATH".to_string(),
        30 => "DT_FLAGS".to_string(),
        32 => "DT_PREINIT_ARRAY".to_string(),
        33 => "DT_PREINIT_ARRAYSZ".to_string(),
        34 => "DT_NUM".to_string(),
        0x6000000d => "DT_LOOS".to_string(),
        0x6ffff000 => "DT_HIOS".to_string(),
        0x6ffffef5 => "DT_GNU_HASH".to_string(),
        0x6ffffef8 => "DT_GNU_CONFLICT".to_string(),
        0x6ffffef9 => "DT_GNU_LIBLIST".to_string(),
        0x6ffffdf5 => "DT_GNU_PRELINKED".to_string(),
        0x6ffffdf6 => "DT_GNU_CONFLICTSZ".to_string(),
        0x6ffffdf7 => "DT_GNU_LIBLISTSZ".to_string(),
        0x6ffffff0 => "DT_VERSYM".to_string(),
        0x6ffffff9 => "DT_RELACOUNT".to_string(),
        0x6ffffffa => "DT_RELCOUNT".to_string(),
        0x6ffffffb => "DT_FLAGS_1".to_string(),
        0x6ffffffc => "DT_VERDEF".to_string(),
        0x6ffffffd => "DT_VERDEFNUM".to_string(),
        0x6ffffffe => "DT_VERNEED".to_string(),
        0x6fffffff => "DT_VERNEEDNUM".to_string(),
        0x70000000 => "DT_LOPROC".to_string(),
        0x7fffffff => "DT_HIPROC".to_string(),
        _ => format!("DT_UNKNOWN(0x{:x})", tag),
    }
}

impl Elf32_Dyn {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let d_tag = i32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap());
        let d_val = u32::from_le_bytes(bytes[offset+4..offset+8].try_into().unwrap());
        Self { d_tag, d_val }
    }

    pub fn print(&self) {
        println!("    Tag: {} (0x{:08X})", get_dtag_name(self.d_tag as i64), self.d_tag);
        println!("    Value/Ptr: 0x{:08X}", self.d_val);
    }
}

impl Elf64_Dyn {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let d_tag = i64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap());
        let d_val = u64::from_le_bytes(bytes[offset+8..offset+16].try_into().unwrap());
        Self { d_tag, d_val }
    }

    pub fn print(&self) {
        println!("    Tag: {} (0x{:016X})", get_dtag_name(self.d_tag), self.d_tag);
        println!("    Value/Ptr: 0x{:016X}", self.d_val);
    }
}
