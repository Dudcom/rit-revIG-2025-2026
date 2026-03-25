#![allow(non_camel_case_types)]

use crate::elf_sectionheaders::{Elf32_Addr, Elf64_Addr};

macro_rules! ELF32_R_SYM {
    ($val:expr) => {
        (($val) >> 8)
    };
}

macro_rules! ELF32_R_TYPE {
    ($val:expr) => {
        (($val) & 0xff)
    };
}

macro_rules! ELF64_R_SYM {
    ($val:expr) => {
        (($val) >> 32)
    };
}

macro_rules! ELF64_R_TYPE {
    ($val:expr) => {
        (($val) & 0xffffffff)
    };
}

pub struct Elf32_Rel {
    pub r_offset: Elf32_Addr,
    pub r_info: u32,
}

pub struct Elf64_Rel {
    pub r_offset: Elf64_Addr,
    pub r_info: u64,
}

pub struct Elf32_Rela {
    pub r_offset: Elf32_Addr,
    pub r_info: u32,
    pub r_addend: i32,
}

pub struct Elf64_Rela {
    pub r_offset: Elf64_Addr,
    pub r_info: u64,
    pub r_addend: i64,
}

impl Elf32_Rel {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let r_offset =
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as Elf32_Addr;
        let r_info = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        Self { r_offset, r_info }
    }

    pub fn print(&self) {
        println!("    Offset: 0x{:08X}", self.r_offset);
        println!(
            "    Info: 0x{:08X} (Sym: {}, Type: {})",
            self.r_info,
            ELF32_R_SYM!(self.r_info),
            ELF32_R_TYPE!(self.r_info)
        );
    }
}

impl Elf64_Rel {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let r_offset =
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as Elf64_Addr;
        let r_info = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
        Self { r_offset, r_info }
    }

    pub fn print(&self) {
        println!("    Offset: 0x{:016X}", self.r_offset);
        println!(
            "    Info: 0x{:016X} (Sym: {}, Type: {})",
            self.r_info,
            ELF64_R_SYM!(self.r_info),
            ELF64_R_TYPE!(self.r_info)
        );
    }
}

impl Elf32_Rela {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let r_offset =
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as Elf32_Addr;
        let r_info = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        let r_addend = i32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap());
        Self {
            r_offset,
            r_info,
            r_addend,
        }
    }

    pub fn print(&self) {
        println!("    Offset: 0x{:08X}", self.r_offset);
        println!(
            "    Info: 0x{:08X} (Sym: {}, Type: {})",
            self.r_info,
            ELF32_R_SYM!(self.r_info),
            ELF32_R_TYPE!(self.r_info)
        );
        println!("    Addend: {}", self.r_addend);
    }
}

impl Elf64_Rela {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let r_offset =
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as Elf64_Addr;
        let r_info = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
        let r_addend = i64::from_le_bytes(bytes[offset + 16..offset + 24].try_into().unwrap());
        Self {
            r_offset,
            r_info,
            r_addend,
        }
    }

    pub fn print(&self) {
        println!("    Offset: 0x{:016X}", self.r_offset);
        println!(
            "    Info: 0x{:016X} (Sym: {}, Type: {})",
            self.r_info,
            ELF64_R_SYM!(self.r_info),
            ELF64_R_TYPE!(self.r_info)
        );
        println!("    Addend: {}", self.r_addend);
    }
}
