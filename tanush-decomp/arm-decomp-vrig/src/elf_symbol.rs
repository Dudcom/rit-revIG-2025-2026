#![allow(non_camel_case_types)]

use crate::elf_sectionheaders::{Elf32_Addr, Elf64_Addr};

macro_rules! ELF32_ST_BIND {
    ($val:expr) => {
        (($val) >> 4)
    };
}
macro_rules! ELF32_ST_TYPE {
    ($val:expr) => {
        ($val & 0xf)
    };
}
macro_rules! ELF32_ST_VISIBILITY {
    ($val:expr) => {
        ($val & 0x3)
    };
}

#[derive(Clone, Copy, PartialEq)]
pub enum ElfSymBind {
    STB_LOCAL,
    STB_GLOBAL,
    STB_WEAK,
    STB_NUM,
    STB_GNU_UNIQUE,
    STB_HIOS,
    STB_LOPROC,
    STB_HIPROC,
    Unknown(u8),
}

impl ElfSymBind {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => ElfSymBind::STB_LOCAL,
            1 => ElfSymBind::STB_GLOBAL,
            2 => ElfSymBind::STB_WEAK,
            3 => ElfSymBind::STB_NUM,
            10 => ElfSymBind::STB_GNU_UNIQUE,
            12 => ElfSymBind::STB_HIOS,
            13 => ElfSymBind::STB_LOPROC,
            15 => ElfSymBind::STB_HIPROC,
            x => ElfSymBind::Unknown(x),
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            ElfSymBind::STB_LOCAL => "STB_LOCAL",
            ElfSymBind::STB_GLOBAL => "STB_GLOBAL",
            ElfSymBind::STB_WEAK => "STB_WEAK",
            ElfSymBind::STB_NUM => "STB_NUM",
            ElfSymBind::STB_GNU_UNIQUE => "STB_GNU_UNIQUE",
            ElfSymBind::STB_HIOS => "STB_HIOS",
            ElfSymBind::STB_LOPROC => "STB_LOPROC",
            ElfSymBind::STB_HIPROC => "STB_HIPROC",
            ElfSymBind::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum ElfSymType {
    STT_NOTYPE,
    STT_OBJECT,
    STT_FUNC,
    STT_SECTION,
    STT_FILE,
    STT_COMMON,
    STT_TLS,
    STT_NUM,
    STT_GNU_IFUNC,
    STT_HIOS,
    STT_LOPROC,
    STT_HIPROC,
    Unknown(u8),
}

impl ElfSymType {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => ElfSymType::STT_NOTYPE,
            1 => ElfSymType::STT_OBJECT,
            2 => ElfSymType::STT_FUNC,
            3 => ElfSymType::STT_SECTION,
            4 => ElfSymType::STT_FILE,
            5 => ElfSymType::STT_COMMON,
            6 => ElfSymType::STT_TLS,
            7 => ElfSymType::STT_NUM,
            10 => ElfSymType::STT_GNU_IFUNC,
            12 => ElfSymType::STT_HIOS,
            13 => ElfSymType::STT_LOPROC,
            15 => ElfSymType::STT_HIPROC,
            x => ElfSymType::Unknown(x),
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            ElfSymType::STT_NOTYPE => "STT_NOTYPE",
            ElfSymType::STT_OBJECT => "STT_OBJECT",
            ElfSymType::STT_FUNC => "STT_FUNC",
            ElfSymType::STT_SECTION => "STT_SECTION",
            ElfSymType::STT_FILE => "STT_FILE",
            ElfSymType::STT_COMMON => "STT_COMMON",
            ElfSymType::STT_TLS => "STT_TLS",
            ElfSymType::STT_NUM => "STT_NUM",
            ElfSymType::STT_GNU_IFUNC => "STT_GNU_IFUNC",
            ElfSymType::STT_HIOS => "STT_HIOS",
            ElfSymType::STT_LOPROC => "STT_LOPROC",
            ElfSymType::STT_HIPROC => "STT_HIPROC",
            ElfSymType::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum ElfSymVisibility {
    STV_DEFAULT,
    STV_INTERNAL,
    STV_HIDDEN,
    STV_PROTECTED,
    Unknown(u8),
}

impl ElfSymVisibility {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => ElfSymVisibility::STV_DEFAULT,
            1 => ElfSymVisibility::STV_INTERNAL,
            2 => ElfSymVisibility::STV_HIDDEN,
            3 => ElfSymVisibility::STV_PROTECTED,
            x => ElfSymVisibility::Unknown(x),
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            ElfSymVisibility::STV_DEFAULT => "STV_DEFAULT",
            ElfSymVisibility::STV_INTERNAL => "STV_INTERNAL",
            ElfSymVisibility::STV_HIDDEN => "STV_HIDDEN",
            ElfSymVisibility::STV_PROTECTED => "STV_PROTECTED",
            ElfSymVisibility::Unknown(_) => "Unknown",
        }
    }
}

// typedef struct {
//     uint32_t      st_name;
//     Elf32_Addr    st_value;
//     uint32_t      st_size;
//     unsigned char st_info;
//     unsigned char st_other;
//     uint16_t      st_shndx;
// } Elf32_Sym;

// typedef struct {
//     uint32_t      st_name;
//     unsigned char st_info;
//     unsigned char st_other;
//     uint16_t      st_shndx;
//     Elf64_Addr    st_value;
//     uint64_t      st_size;
// } Elf64_Sym;

pub struct Elf32_Sym {
    pub st_name: u32,
    pub st_value: Elf32_Addr,
    pub st_size: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_bind: ElfSymBind,
    pub st_type: ElfSymType,
    pub st_visibility: ElfSymVisibility,
}

pub struct Elf64_Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: Elf64_Addr,
    pub st_size: u64,
    pub st_bind: ElfSymBind,
    pub st_type: ElfSymType,
    pub st_visibility: ElfSymVisibility,
}

impl Elf32_Sym {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let st_name = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let st_value =
            u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as Elf32_Addr;
        let st_size = u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap());
        let st_info = bytes[offset + 12];
        let st_other = bytes[offset + 13];
        let st_shndx = u16::from_le_bytes(bytes[offset + 14..offset + 16].try_into().unwrap());
        let st_bind = ElfSymBind::from_raw(ELF32_ST_BIND!(st_info));
        let st_type = ElfSymType::from_raw(ELF32_ST_TYPE!(st_info));
        let st_visibility = ElfSymVisibility::from_raw(ELF32_ST_VISIBILITY!(st_other));
        Self {
            st_name,
            st_value,
            st_size,
            st_info,
            st_other,
            st_shndx,
            st_bind,
            st_type,
            st_visibility,
        }
    }

    pub fn print(&self) {
        println!("    Name: {}", self.st_name);
        println!("    Value: 0x{:08X}", self.st_value);
        println!("    Size: 0x{:08X}", self.st_size);
        println!(
            "    Info: {} {}",
            self.st_bind.type_name(),
            self.st_type.type_name()
        );
        println!(
            "    Other: {} (0x{:02X})",
            self.st_visibility.type_name(),
            self.st_other
        );
        println!("    Shndx: 0x{:04X}", self.st_shndx);
    }
}

impl Elf64_Sym {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let st_name = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let st_info = bytes[offset + 4];
        let st_other = bytes[offset + 5];
        let st_shndx = u16::from_le_bytes(bytes[offset + 6..offset + 8].try_into().unwrap());
        let st_value =
            u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap()) as Elf64_Addr;
        let st_size = u64::from_le_bytes(bytes[offset + 16..offset + 24].try_into().unwrap());
        let st_bind = ElfSymBind::from_raw(ELF32_ST_BIND!(st_info));
        let st_type = ElfSymType::from_raw(ELF32_ST_TYPE!(st_info));
        let st_visibility = ElfSymVisibility::from_raw(ELF32_ST_VISIBILITY!(st_other));
        Self {
            st_name,
            st_info,
            st_other,
            st_shndx,
            st_value,
            st_size,
            st_bind,
            st_type,
            st_visibility,
        }
    }

    pub fn print(&self) {
        println!("    Name: {}", self.st_name);
        println!("    Value: 0x{:016X}", self.st_value);
        println!("    Size: 0x{:016X}", self.st_size);
        println!(
            "    Info: {} {}",
            self.st_bind.type_name(),
            self.st_type.type_name()
        );
        println!(
            "    Other: {} (0x{:02X})",
            self.st_visibility.type_name(),
            self.st_other
        );
        println!("    Shndx: 0x{:04X}", self.st_shndx);
    }
}
