

use crate::elf_sectionheaders::{Elf32_Addr, Elf64_Addr};

// #define ELF32_ST_BIND(val)                (((unsigned char) (val)) >> 4)
// #define ELF32_ST_TYPE(val)                ((val) & 0xf)
// #define ELF32_ST_INFO(bind, type)        (((bind) << 4) + ((type) & 0xf))
// the 64 bit macros are the same as the 32 bit macros so I am just not going to repeat them here
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
macro_rules! ELF32_ST_INFO {
    ($bind:expr, $type:expr) => {
        (($bind << 4) + ($type & 0xf))
    };
}

macro_rules! ELF32_ST_VISIBILITY {
    ($val:expr) => {
        ($val & 0x3)
    };
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
}

pub struct Elf64_Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: Elf64_Addr,
    pub st_size: u64,
}



fn get_bind_string(bind: u8) -> String {
    match bind {
        0 => "STB_LOCAL".to_string(),
        1 => "STB_GLOBAL".to_string(),
        2 => "STB_WEAK".to_string(),
        3 => "STB_NUM".to_string(),
        10 => "STB_GNU_UNIQUE".to_string(),
        12 => "STB_HIOS".to_string(),
        13 => "STB_LOPROC".to_string(),
        15 => "STB_HIPROC".to_string(),
        _ => "Unknown".to_string(),
    }
}


fn get_sym_type_string(sym_type: u8) -> String {
    match sym_type {
        0 => "STT_NOTYPE".to_string(),
        1 => "STT_OBJECT".to_string(),
        2 => "STT_FUNC".to_string(),
        3 => "STT_SECTION".to_string(),
        4 => "STT_FILE".to_string(),
        5 => "STT_COMMON".to_string(),
        6 => "STT_TLS".to_string(),
        7 => "STT_NUM".to_string(),
        10 => "STT_GNU_IFUNC".to_string(),
        12 => "STT_HIOS".to_string(),
        13 => "STT_LOPROC".to_string(),
        15 => "STT_HIPROC".to_string(),
        _ => "Unknown".to_string(),
    }
}


fn get_visibility_string(visibility: u8) -> String {
    match visibility {
        0 => "STV_DEFAULT".to_string(),
        1 => "STV_INTERNAL".to_string(),
        2 => "STV_HIDDEN".to_string(),
        3 => "STV_PROTECTED".to_string(),
        _ => "Unknown".to_string(),
    }
}

impl Elf32_Sym {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let st_name = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap());
        let st_value = u32::from_le_bytes(bytes[offset+4..offset+8].try_into().unwrap()) as Elf32_Addr;
        let st_size = u32::from_le_bytes(bytes[offset+8..offset+12].try_into().unwrap());
        let st_info = bytes[offset+12];
        let st_other = bytes[offset+13];
        let st_shndx = u16::from_le_bytes(bytes[offset+14..offset+16].try_into().unwrap());
        Self { st_name, st_value, st_size, st_info, st_other, st_shndx }
    }
    
    pub fn get_info_string(&self) -> String {
        let bind = ELF32_ST_BIND!(self.st_info);
        let bind_string = get_bind_string(bind);
        
        let sym_type = ELF32_ST_TYPE!(self.st_info);
        let sym_type_string = get_sym_type_string(sym_type);
        format!("{} {}", bind_string, sym_type_string)
    }
    
    pub fn print(&self) {
        println!("    Name: {}", self.st_name);
        println!("    Value: 0x{:08X}", self.st_value);
        println!("    Size: 0x{:08X}", self.st_size);
        println!("    Info: {}", self.get_info_string());
        println!("    Other: {} (0x{:02X})", get_visibility_string(ELF32_ST_VISIBILITY!(self.st_other)), self.st_other);
        println!("    Shndx: 0x{:04X}", self.st_shndx);
    }
}

impl Elf64_Sym {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let st_name = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap());
        let st_info = bytes[offset+4];
        let st_other = bytes[offset+5];
        let st_shndx = u16::from_le_bytes(bytes[offset+6..offset+8].try_into().unwrap());
        let st_value = u64::from_le_bytes(bytes[offset+8..offset+16].try_into().unwrap()) as Elf64_Addr;
        let st_size = u64::from_le_bytes(bytes[offset+16..offset+24].try_into().unwrap());
        Self { st_name, st_info, st_other, st_shndx, st_value, st_size }
    }

    pub fn get_info_string(&self) -> String {
        let bind = ELF32_ST_BIND!(self.st_info);
        let bind_string = get_bind_string(bind);
        
        let sym_type = ELF32_ST_TYPE!(self.st_info);
        let sym_type_string = get_sym_type_string(sym_type);
        format!("{} {}", bind_string, sym_type_string)
    }

    pub fn print(&self) {
        println!("    Name: {}", self.st_name);
        println!("    Value: 0x{:016X}", self.st_value);
        println!("    Size: 0x{:016X}", self.st_size);
        println!("    Info: {}", self.get_info_string());
        println!("    Other: {} (0x{:02X})", get_visibility_string(ELF32_ST_VISIBILITY!(self.st_other)), self.st_other);
        println!("    Shndx: 0x{:04X}", self.st_shndx);
    }
}


