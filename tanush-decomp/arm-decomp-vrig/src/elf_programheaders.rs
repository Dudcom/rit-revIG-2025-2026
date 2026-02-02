
use crate::elf_header::{Elf32_Phdr, Elf64_Phdr, ElfNAddr, ElfNOff, ElfPhdrType};

impl Elf32_Phdr {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let start = offset;
        let p_type_raw = u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap());
        Self {
            p_type: ElfPhdrType::from_raw(p_type_raw),
            p_offset: u32::from_le_bytes(bytes[start + 4..start + 8].try_into().unwrap()) as ElfNOff,
            p_vaddr: u32::from_le_bytes(bytes[start + 8..start + 12].try_into().unwrap()) as ElfNAddr,
            p_paddr: u32::from_le_bytes(bytes[start + 12..start + 16].try_into().unwrap()) as ElfNAddr,
            p_filesz: u32::from_le_bytes(bytes[start + 16..start + 20].try_into().unwrap()),
            p_memsz: u32::from_le_bytes(bytes[start + 20..start + 24].try_into().unwrap()),
            p_flags: u32::from_le_bytes(bytes[start + 24..start + 28].try_into().unwrap()),
            p_align: u32::from_le_bytes(bytes[start + 28..start + 32].try_into().unwrap()),
        }
    }

    pub fn get_flags_string(&self) -> String {
        let mut flags = Vec::new();
        if self.p_flags & 0x1 != 0 {
            flags.push("PF_X");
        }
        if self.p_flags & 0x2 != 0 {
            flags.push("PF_W");
        }
        if self.p_flags & 0x4 != 0 {
            flags.push("PF_R");
        }
        if flags.is_empty() {
            "PF_NONE".to_string()
        } else {
            flags.join(" | ")
        }
    }

    pub fn print(&self, index: usize) {
        println!("Program Header {}:", index);
        println!("  Type: {} (0x{:08X})", self.p_type.type_name(), self.p_type.as_raw());
        println!("  Offset: 0x{:016X}", self.p_offset);
        println!("  Virtual Address: 0x{:016X}", self.p_vaddr);
        println!("  Physical Address: 0x{:016X}", self.p_paddr);
        println!("  File Size: 0x{:08X} ({} bytes)", self.p_filesz, self.p_filesz);
        println!("  Memory Size: 0x{:08X} ({} bytes)", self.p_memsz, self.p_memsz);
        println!("  Flags: {} (0x{:08X})", self.get_flags_string(), self.p_flags);
        println!("  Align: 0x{:08X}", self.p_align);
    }
}

impl Elf64_Phdr {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let start = offset;
        let p_type_raw = u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap());
        Self {
            p_type: ElfPhdrType::from_raw(p_type_raw),
            p_flags: u32::from_le_bytes(bytes[start + 4..start + 8].try_into().unwrap()),
            p_offset: u64::from_le_bytes(bytes[start + 8..start + 16].try_into().unwrap()),
            p_vaddr: u64::from_le_bytes(bytes[start + 16..start + 24].try_into().unwrap()),
            p_paddr: u64::from_le_bytes(bytes[start + 24..start + 32].try_into().unwrap()),
            p_filesz: u64::from_le_bytes(bytes[start + 32..start + 40].try_into().unwrap()),
            p_memsz: u64::from_le_bytes(bytes[start + 40..start + 48].try_into().unwrap()),
            p_align: u64::from_le_bytes(bytes[start + 48..start + 56].try_into().unwrap()),
        }
    }

    pub fn get_flags_string(&self) -> String {
        let mut flags = Vec::new();
        if self.p_flags & 0x1 != 0 {
            flags.push("PF_X");
        }
        if self.p_flags & 0x2 != 0 {
            flags.push("PF_W");
        }
        if self.p_flags & 0x4 != 0 {
            flags.push("PF_R");
        }
        if flags.is_empty() {
            "PF_NONE".to_string()
        } else {
            flags.join(" | ")
        }
    }

    pub fn print(&self, index: usize) {
        println!("Program Header {}:", index);
        println!("  Type: {} (0x{:08X})", self.p_type.type_name(), self.p_type.as_raw());
        println!("  Flags: {} (0x{:08X})", self.get_flags_string(), self.p_flags);
        println!("  Offset: 0x{:016X}", self.p_offset);
        println!("  Virtual Address: 0x{:016X}", self.p_vaddr);
        println!("  Physical Address: 0x{:016X}", self.p_paddr);
        println!("  File Size: 0x{:016X} ({} bytes)", self.p_filesz, self.p_filesz);
        println!("  Memory Size: 0x{:016X} ({} bytes)", self.p_memsz, self.p_memsz);
        println!("  Align: 0x{:016X}", self.p_align);
        println!();
    }
}