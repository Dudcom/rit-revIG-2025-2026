#![allow(non_camel_case_types)]


#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ElfDynTag {
    DT_NULL,
    DT_NEEDED,
    DT_PLTRELSZ,
    DT_PLTGOT,
    DT_HASH,
    DT_STRTAB,
    DT_SYMTAB,
    DT_RELA,
    DT_RELASZ,
    DT_RELAENT,
    DT_STRSZ,
    DT_SYMENT,
    DT_INIT,
    DT_FINI,
    DT_SONAME,
    DT_RPATH,
    DT_SYMBOLIC,
    DT_REL,
    DT_RELSZ,
    DT_RELENT,
    DT_PLTREL,
    DT_DEBUG,
    DT_TEXTREL,
    DT_JMPREL,
    DT_BIND_NOW,
    DT_INIT_ARRAY,
    DT_FINI_ARRAY,
    DT_INIT_ARRAYSZ,
    DT_FINI_ARRAYSZ,
    DT_RUNPATH,
    DT_FLAGS,
    DT_PREINIT_ARRAY,
    DT_PREINIT_ARRAYSZ,
    DT_NUM,
    DT_LOOS,
    DT_HIOS,
    DT_GNU_HASH,
    DT_GNU_CONFLICT,
    DT_GNU_LIBLIST,
    DT_GNU_PRELINKED,
    DT_GNU_CONFLICTSZ,
    DT_GNU_LIBLISTSZ,
    DT_VERSYM,
    DT_RELACOUNT,
    DT_RELCOUNT,
    DT_FLAGS_1,
    DT_VERDEF,
    DT_VERDEFNUM,
    DT_VERNEED,
    DT_VERNEEDNUM,
    DT_LOPROC,
    DT_HIPROC,
    Unknown(i64),
}

impl ElfDynTag {
    pub fn from_raw_i32(v: i32) -> Self {
        Self::from_raw(v as i64)
    }
    pub fn from_raw(v: i64) -> Self {
        match v {
            0 => ElfDynTag::DT_NULL,
            1 => ElfDynTag::DT_NEEDED,
            2 => ElfDynTag::DT_PLTRELSZ,
            3 => ElfDynTag::DT_PLTGOT,
            4 => ElfDynTag::DT_HASH,
            5 => ElfDynTag::DT_STRTAB,
            6 => ElfDynTag::DT_SYMTAB,
            7 => ElfDynTag::DT_RELA,
            8 => ElfDynTag::DT_RELASZ,
            9 => ElfDynTag::DT_RELAENT,
            10 => ElfDynTag::DT_STRSZ,
            11 => ElfDynTag::DT_SYMENT,
            12 => ElfDynTag::DT_INIT,
            13 => ElfDynTag::DT_FINI,
            14 => ElfDynTag::DT_SONAME,
            15 => ElfDynTag::DT_RPATH,
            16 => ElfDynTag::DT_SYMBOLIC,
            17 => ElfDynTag::DT_REL,
            18 => ElfDynTag::DT_RELSZ,
            19 => ElfDynTag::DT_RELENT,
            20 => ElfDynTag::DT_PLTREL,
            21 => ElfDynTag::DT_DEBUG,
            22 => ElfDynTag::DT_TEXTREL,
            23 => ElfDynTag::DT_JMPREL,
            24 => ElfDynTag::DT_BIND_NOW,
            25 => ElfDynTag::DT_INIT_ARRAY,
            26 => ElfDynTag::DT_FINI_ARRAY,
            27 => ElfDynTag::DT_INIT_ARRAYSZ,
            28 => ElfDynTag::DT_FINI_ARRAYSZ,
            29 => ElfDynTag::DT_RUNPATH,
            30 => ElfDynTag::DT_FLAGS,
            32 => ElfDynTag::DT_PREINIT_ARRAY,
            33 => ElfDynTag::DT_PREINIT_ARRAYSZ,
            34 => ElfDynTag::DT_NUM,
            0x6000000d => ElfDynTag::DT_LOOS,
            0x6ffff000 => ElfDynTag::DT_HIOS,
            0x6ffffef5 => ElfDynTag::DT_GNU_HASH,
            0x6ffffef8 => ElfDynTag::DT_GNU_CONFLICT,
            0x6ffffef9 => ElfDynTag::DT_GNU_LIBLIST,
            0x6ffffdf5 => ElfDynTag::DT_GNU_PRELINKED,
            0x6ffffdf6 => ElfDynTag::DT_GNU_CONFLICTSZ,
            0x6ffffdf7 => ElfDynTag::DT_GNU_LIBLISTSZ,
            0x6ffffff0 => ElfDynTag::DT_VERSYM,
            0x6ffffff9 => ElfDynTag::DT_RELACOUNT,
            0x6ffffffa => ElfDynTag::DT_RELCOUNT,
            0x6ffffffb => ElfDynTag::DT_FLAGS_1,
            0x6ffffffc => ElfDynTag::DT_VERDEF,
            0x6ffffffd => ElfDynTag::DT_VERDEFNUM,
            0x6ffffffe => ElfDynTag::DT_VERNEED,
            0x6fffffff => ElfDynTag::DT_VERNEEDNUM,
            0x70000000 => ElfDynTag::DT_LOPROC,
            0x7fffffff => ElfDynTag::DT_HIPROC,
            x => ElfDynTag::Unknown(x),
        }
    }
    pub fn as_raw_i32(&self) -> i32 {
        self.as_raw() as i32
    }
    pub fn as_raw(&self) -> i64 {
        match self {
            ElfDynTag::DT_NULL => 0,
            ElfDynTag::DT_NEEDED => 1,
            ElfDynTag::DT_PLTRELSZ => 2,
            ElfDynTag::DT_PLTGOT => 3,
            ElfDynTag::DT_HASH => 4,
            ElfDynTag::DT_STRTAB => 5,
            ElfDynTag::DT_SYMTAB => 6,
            ElfDynTag::DT_RELA => 7,
            ElfDynTag::DT_RELASZ => 8,
            ElfDynTag::DT_RELAENT => 9,
            ElfDynTag::DT_STRSZ => 10,
            ElfDynTag::DT_SYMENT => 11,
            ElfDynTag::DT_INIT => 12,
            ElfDynTag::DT_FINI => 13,
            ElfDynTag::DT_SONAME => 14,
            ElfDynTag::DT_RPATH => 15,
            ElfDynTag::DT_SYMBOLIC => 16,
            ElfDynTag::DT_REL => 17,
            ElfDynTag::DT_RELSZ => 18,
            ElfDynTag::DT_RELENT => 19,
            ElfDynTag::DT_PLTREL => 20,
            ElfDynTag::DT_DEBUG => 21,
            ElfDynTag::DT_TEXTREL => 22,
            ElfDynTag::DT_JMPREL => 23,
            ElfDynTag::DT_BIND_NOW => 24,
            ElfDynTag::DT_INIT_ARRAY => 25,
            ElfDynTag::DT_FINI_ARRAY => 26,
            ElfDynTag::DT_INIT_ARRAYSZ => 27,
            ElfDynTag::DT_FINI_ARRAYSZ => 28,
            ElfDynTag::DT_RUNPATH => 29,
            ElfDynTag::DT_FLAGS => 30,
            ElfDynTag::DT_PREINIT_ARRAY => 32,
            ElfDynTag::DT_PREINIT_ARRAYSZ => 33,
            ElfDynTag::DT_NUM => 34,
            ElfDynTag::DT_LOOS => 0x6000000d,
            ElfDynTag::DT_HIOS => 0x6ffff000,
            ElfDynTag::DT_GNU_HASH => 0x6ffffef5,
            ElfDynTag::DT_GNU_CONFLICT => 0x6ffffef8,
            ElfDynTag::DT_GNU_LIBLIST => 0x6ffffef9,
            ElfDynTag::DT_GNU_PRELINKED => 0x6ffffdf5,
            ElfDynTag::DT_GNU_CONFLICTSZ => 0x6ffffdf6,
            ElfDynTag::DT_GNU_LIBLISTSZ => 0x6ffffdf7,
            ElfDynTag::DT_VERSYM => 0x6ffffff0,
            ElfDynTag::DT_RELACOUNT => 0x6ffffff9,
            ElfDynTag::DT_RELCOUNT => 0x6ffffffa,
            ElfDynTag::DT_FLAGS_1 => 0x6ffffffb,
            ElfDynTag::DT_VERDEF => 0x6ffffffc,
            ElfDynTag::DT_VERDEFNUM => 0x6ffffffd,
            ElfDynTag::DT_VERNEED => 0x6ffffffe,
            ElfDynTag::DT_VERNEEDNUM => 0x6fffffff,
            ElfDynTag::DT_LOPROC => 0x70000000,
            ElfDynTag::DT_HIPROC => 0x7fffffff,
            ElfDynTag::Unknown(x) => *x,
        }
    }
    pub fn type_name(&self) -> String {
        match self {
            ElfDynTag::Unknown(x) => format!("DT_UNKNOWN(0x{:x})", x),
            _ => format!("{:?}", self).replace("ElfDynTag::", ""),
        }
    }
}

pub struct Elf32_Dyn {
    pub d_tag: ElfDynTag,
    pub d_val: u32,
}

pub struct Elf64_Dyn {
    pub d_tag: ElfDynTag,
    pub d_val: u64,
}

impl Elf32_Dyn {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let d_tag_raw = i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let d_val = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        Self { d_tag: ElfDynTag::from_raw_i32(d_tag_raw), d_val }
    }

    pub fn print(&self) {
        println!("    Tag: {} (0x{:08X})", self.d_tag.type_name(), self.d_tag.as_raw_i32() as u32);
        println!("    Value/Ptr: 0x{:08X}", self.d_val);
    }
}

impl Elf64_Dyn {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let d_tag_raw = i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let d_val = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
        Self { d_tag: ElfDynTag::from_raw(d_tag_raw), d_val }
    }

    pub fn print(&self) {
        println!("    Tag: {} (0x{:016X})", self.d_tag.type_name(), self.d_tag.as_raw());
        println!("    Value/Ptr: 0x{:016X}", self.d_val);
    }
}
