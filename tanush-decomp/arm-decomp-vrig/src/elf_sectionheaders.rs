

pub type Elf32_Addr = u32;
pub type Elf64_Addr = u64;
pub type Elf32_Off = u32;
pub type Elf64_Off = u64;

// typedef uint32_t Elf32_Addr;
// typedef uint64_t Elf64_Addr;
// typedef uint32_t Elf32_Off;
// typedef uint64_t Elf64_Off;
// https://sites.uclouvain.be/SystInfo/usr/include/elf.h.html

pub struct Elf32_Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u32,
    pub sh_addr: Elf32_Addr,
    pub sh_offset: Elf32_Off,
    pub sh_size: u32,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u32,
    pub sh_entsize: u32,
}

pub struct Elf64_Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: Elf64_Addr,
    pub sh_offset: Elf64_Off,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

impl Elf32_Shdr {

        //    typedef struct {
        //        uint32_t   sh_name;
        //        uint32_t   sh_type;
        //        uint32_t   sh_flags;
        //        Elf32_Addr sh_addr;
        //        Elf32_Off  sh_offset;
        //        uint32_t   sh_size;
        //        uint32_t   sh_link;
        //        uint32_t   sh_info;
        //        uint32_t   sh_addralign;
        //        uint32_t   sh_entsize;
        //    } Elf32_Shdr;

    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let start = offset;
        Self {
            sh_name: u32::from_le_bytes(bytes[start..start+4].try_into().unwrap()),
            sh_type: u32::from_le_bytes(bytes[start+4..start+8].try_into().unwrap()),
            sh_flags: u32::from_le_bytes(bytes[start+8..start+12].try_into().unwrap()),
            sh_addr: u32::from_le_bytes(bytes[start+12..start+16].try_into().unwrap()) as Elf32_Addr,
            sh_offset: u32::from_le_bytes(bytes[start+16..start+20].try_into().unwrap()) as Elf32_Off,
            sh_size: u32::from_le_bytes(bytes[start+20..start+24].try_into().unwrap()),
            sh_link: u32::from_le_bytes(bytes[start+24..start+28].try_into().unwrap()),
            sh_info: u32::from_le_bytes(bytes[start+28..start+32].try_into().unwrap()),
            sh_addralign: u32::from_le_bytes(bytes[start+32..start+36].try_into().unwrap()),
            sh_entsize: u32::from_le_bytes(bytes[start+36..start+40].try_into().unwrap()),
        }
    }
    pub fn get_type_name(&self) -> &str {
        match self.sh_type {
            0 => "SHT_NULL",
            1 => "SHT_PROGBITS",
            2 => "SHT_SYMTAB",
            3 => "SHT_STRTAB",
            4 => "SHT_RELA",
            5 => "SHT_HASH",
            6 => "SHT_DYNAMIC",
            7 => "SHT_NOTE",
            8 => "SHT_NOBITS",
            9 => "SHT_REL",
            10 => "SHT_SHLIB",
            11 => "SHT_DYNSYM",
            14 => "SHT_INIT_ARRAY",
            15 => "SHT_FINI_ARRAY",
            16 => "SHT_PREINIT_ARRAY",
            17 => "SHT_GROUP",
            18 => "SHT_SYMTAB_SHNDX",
            19 => "SHT_NUM",
            0x6ffffff5 => "SHT_GNU_ATTRIBUTES",
            0x6ffffff6 => "SHT_GNU_HASH",
            0x6ffffff7 => "SHT_GNU_LIBLIST",
            0x6ffffff8 => "SHT_CHECKSUM",
            0x6ffffffa => "SHT_SUNW_move",
            0x6ffffffb => "SHT_SUNW_COMDAT",
            0x6ffffffc => "SHT_SUNW_syminfo",
            0x6ffffffd => "SHT_GNU_verdef",
            0x6ffffffe => "SHT_GNU_verneed",
            0x6fffffff => "SHT_GNU_versym",
            0x70000000 => "SHT_MIPS_LIBLIST",
            0x70000001 => "SHT_MIPS_MSYM",
            0x70000002 => "SHT_MIPS_CONFLICT",
            0x70000003 => "SHT_MIPS_GPTAB",
            0x70000004 => "SHT_MIPS_UCODE",
            0x70000005 => "SHT_MIPS_DEBUG",
            0x70000006 => "SHT_MIPS_REGINFO",
            0x70000007 => "SHT_MIPS_PACKAGE",
            0x70000008 => "SHT_MIPS_PACKSYM",
            0x70000009 => "SHT_MIPS_RELD",
            0x7000000b => "SHT_MIPS_IFACE",
            0x7000000c => "SHT_MIPS_CONTENT",
            0x7000000d => "SHT_MIPS_OPTIONS",
            0x70000010 => "SHT_MIPS_SHDR",
            0x70000011 => "SHT_MIPS_FDESC",
            0x70000012 => "SHT_MIPS_EXTSYM",
            0x70000013 => "SHT_MIPS_DENSE",
            0x70000014 => "SHT_MIPS_PDESC",
            0x70000015 => "SHT_MIPS_LOCSYM",
            0x70000016 => "SHT_MIPS_AUXSYM",
            0x70000017 => "SHT_MIPS_OPTSYM",
            0x70000018 => "SHT_MIPS_LOCSTR",
            0x70000019 => "SHT_MIPS_LINE",
            0x7000001a => "SHT_MIPS_RFDESC",
            0x7000001b => "SHT_MIPS_DELTASYM",
            0x7000001c => "SHT_MIPS_DELTAINST",
            0x7000001d => "SHT_MIPS_DELTACLASS",
            0x7000001e => "SHT_MIPS_DWARF",
            0x7000001f => "SHT_MIPS_DELTADECL",
            0x70000020 => "SHT_MIPS_SYMBOL_LIB",
            0x70000021 => "SHT_MIPS_EVENTS",
            0x70000022 => "SHT_MIPS_TRANSLATE",
            0x70000023 => "SHT_MIPS_PIXIE",
            0x70000024 => "SHT_MIPS_XLATE",
            0x70000025 => "SHT_MIPS_XLATE_DEBUG",
            0x70000026 => "SHT_MIPS_WHIRL",
            0x70000027 => "SHT_MIPS_EH_REGION",
            0x70000028 => "SHT_MIPS_XLATE_OLD",
            0x70000029 => "SHT_MIPS_PDR_EXCEPTION",
            _ => "UNKNOWN/MIPS_VENDOR",
        }
    }

    pub fn get_flags_string(&self) -> String {
        let mut flags = Vec::new();
        
        if self.sh_flags & 0x1 != 0 {
            flags.push("SHF_WRITE");
        }
        if self.sh_flags & 0x2 != 0 {
            flags.push("SHF_ALLOC");
        }
        if self.sh_flags & 0x4 != 0 {
            flags.push("SHF_EXECINSTR");
        }
        if self.sh_flags & 0x10 != 0 {
            flags.push("SHF_MERGE");
        }
        if self.sh_flags & 0x20 != 0 {
            flags.push("SHF_STRINGS");
        }
        if self.sh_flags & 0x40 != 0 {
            flags.push("SHF_INFO_LINK");
        }
        if self.sh_flags & 0x80 != 0 {
            flags.push("SHF_LINK_ORDER");
        }
        if self.sh_flags & 0x100 != 0 {
            flags.push("SHF_OS_NONCONFORMING");
        }
        if self.sh_flags & 0x200 != 0 {
            flags.push("SHF_GROUP");
        }
        if self.sh_flags & 0x400 != 0 {
            flags.push("SHF_TLS");
        }
        if self.sh_flags & 0x40000000 != 0 {
            flags.push("SHF_ORDERED");
        }
        if self.sh_flags & 0x80000000 != 0 {
            flags.push("SHF_EXCLUDE");
        }
        
        if flags.is_empty() {
            "".to_string()
        } else {
            flags.join(", ")
        }
    }

    pub fn print(&self, index: usize, bytes: &[u8]) {
        println!("Section Header {}:", index);
        println!("  Name: {}", self.sh_name);
        let type_name = self.get_type_name();
        println!("  Type: {}", type_name);
        println!("  Flags: {} (0x{:08X})", self.get_flags_string(), self.sh_flags);
        println!("  Address: 0x{:08X}", self.sh_addr);
        println!("  Offset: 0x{:08X}", self.sh_offset);
        println!("  Size: 0x{:08X}", self.sh_size);
        
        if type_name == "SHT_SYMTAB" || type_name == "SHT_DYNSYM" {
            if self.sh_entsize > 0 && self.sh_size > 0 {
                let num_symbols = (self.sh_size / self.sh_entsize) as usize;
                println!("  Symbols ({} entries):", num_symbols);
                for i in 0..num_symbols {
                    let offset = self.sh_offset as usize + (i * self.sh_entsize as usize);
                    if offset + 16 <= bytes.len() {
                        let sym = crate::elf_symbol::Elf32_Sym::read_bytes(bytes, offset);
                        println!("    Symbol {}:", i);
                        sym.print();
                    }
                }
            }
        }
        
        if type_name == "SHT_RELA" {
            if self.sh_entsize > 0 && self.sh_size > 0 {
                let num_entries = (self.sh_size / self.sh_entsize) as usize;
                println!("  Relocations with addends ({} entries):", num_entries);
                for i in 0..num_entries {
                    let offset = self.sh_offset as usize + (i * self.sh_entsize as usize);
                    if offset + 12 <= bytes.len() {
                        let rela = crate::elf_relocation::Elf32_Rela::read_bytes(bytes, offset);
                        println!("    Relocation {}:", i);
                        rela.print();
                    }
                }
            }
        }
        
        if type_name == "SHT_REL" {
            if self.sh_entsize > 0 && self.sh_size > 0 {
                let num_entries = (self.sh_size / self.sh_entsize) as usize;
                println!("  Relocations ({} entries):", num_entries);
                for i in 0..num_entries {
                    let offset = self.sh_offset as usize + (i * self.sh_entsize as usize);
                    if offset + 8 <= bytes.len() {
                        let rel = crate::elf_relocation::Elf32_Rel::read_bytes(bytes, offset);
                        println!("    Relocation {}:", i);
                        rel.print();
                    }
                }
            }
        }
        
        if type_name == "SHT_DYNAMIC" {
            if self.sh_entsize > 0 && self.sh_size > 0 {
                let num_entries = (self.sh_size / self.sh_entsize) as usize;
                println!("  Dynamic entries ({} entries):", num_entries);
                for i in 0..num_entries {
                    let offset = self.sh_offset as usize + (i * self.sh_entsize as usize);
                    if offset + 8 <= bytes.len() {
                        let dyn_entry = crate::elf_dynamic::Elf32_Dyn::read_bytes(bytes, offset);
                        println!("    Dynamic {}:", i);
                        dyn_entry.print();
                        if dyn_entry.d_tag == 0 {
                            break;
                        }
                    }
                }
            }
        }
        
        if type_name == "SHT_NOTE" {
            if self.sh_size > 0 {
                let offset = self.sh_offset as usize;
                if offset + 12 <= bytes.len() {
                    let note = crate::elf_notes::Elf32_Nhdr::read_bytes(bytes, offset);
                    println!("  Note:");
                    note.print(bytes, offset);
                }
            }
        }
    }

}





impl Elf64_Shdr {

    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let start = offset;
        Self {
            sh_name: u32::from_le_bytes(bytes[start..start+4].try_into().unwrap()),
            sh_type: u32::from_le_bytes(bytes[start+4..start+8].try_into().unwrap()),
            sh_flags: u64::from_le_bytes(bytes[start+8..start+16].try_into().unwrap()),
            sh_addr: u64::from_le_bytes(bytes[start+16..start+24].try_into().unwrap()) as Elf64_Addr,
            sh_offset: u64::from_le_bytes(bytes[start+24..start+32].try_into().unwrap()) as Elf64_Off,
            sh_size: u64::from_le_bytes(bytes[start+32..start+40].try_into().unwrap()),
            sh_link: u32::from_le_bytes(bytes[start+40..start+44].try_into().unwrap()),
            sh_info: u32::from_le_bytes(bytes[start+44..start+48].try_into().unwrap()),
            sh_addralign: u64::from_le_bytes(bytes[start+48..start+56].try_into().unwrap()),
            sh_entsize: u64::from_le_bytes(bytes[start+56..start+64].try_into().unwrap()),
        }
    }

    pub fn get_type_name(&self) -> &str {
        match self.sh_type {
            0 => "SHT_NULL",
            1 => "SHT_PROGBITS",
            2 => "SHT_SYMTAB",
            3 => "SHT_STRTAB",
            4 => "SHT_RELA",
            5 => "SHT_HASH",
            6 => "SHT_DYNAMIC",
            7 => "SHT_NOTE",
            8 => "SHT_NOBITS",
            9 => "SHT_REL",
            10 => "SHT_SHLIB",
            11 => "SHT_DYNSYM",
            14 => "SHT_INIT_ARRAY",
            15 => "SHT_FINI_ARRAY",
            16 => "SHT_PREINIT_ARRAY",
            17 => "SHT_GROUP",
            18 => "SHT_SYMTAB_SHNDX",
            19 => "SHT_NUM",
            0x6ffffff5 => "SHT_GNU_ATTRIBUTES",
            0x6ffffff6 => "SHT_GNU_HASH",
            0x6ffffff7 => "SHT_GNU_LIBLIST",
            0x6ffffff8 => "SHT_CHECKSUM",
            0x6ffffffa => "SHT_SUNW_move",
            0x6ffffffb => "SHT_SUNW_COMDAT",
            0x6ffffffc => "SHT_SUNW_syminfo",
            0x6ffffffd => "SHT_GNU_verdef",
            0x6ffffffe => "SHT_GNU_verneed",
            0x6fffffff => "SHT_GNU_versym",
            0x70000000 => "SHT_MIPS_LIBLIST",
            0x70000001 => "SHT_MIPS_MSYM",
            0x70000002 => "SHT_MIPS_CONFLICT",
            0x70000003 => "SHT_MIPS_GPTAB",
            0x70000004 => "SHT_MIPS_UCODE",
            0x70000005 => "SHT_MIPS_DEBUG",
            0x70000006 => "SHT_MIPS_REGINFO",
            0x70000007 => "SHT_MIPS_PACKAGE",
            0x70000008 => "SHT_MIPS_PACKSYM",
            0x70000009 => "SHT_MIPS_RELD",
            0x7000000b => "SHT_MIPS_IFACE",
            0x7000000c => "SHT_MIPS_CONTENT",
            0x7000000d => "SHT_MIPS_OPTIONS",
            0x70000010 => "SHT_MIPS_SHDR",
            0x70000011 => "SHT_MIPS_FDESC",
            0x70000012 => "SHT_MIPS_EXTSYM",
            0x70000013 => "SHT_MIPS_DENSE",
            0x70000014 => "SHT_MIPS_PDESC",
            0x70000015 => "SHT_MIPS_LOCSYM",
            0x70000016 => "SHT_MIPS_AUXSYM",
            0x70000017 => "SHT_MIPS_OPTSYM",
            0x70000018 => "SHT_MIPS_LOCSTR",
            0x70000019 => "SHT_MIPS_LINE",
            0x7000001a => "SHT_MIPS_RFDESC",
            0x7000001b => "SHT_MIPS_DELTASYM",
            0x7000001c => "SHT_MIPS_DELTAINST",
            0x7000001d => "SHT_MIPS_DELTACLASS",
            0x7000001e => "SHT_MIPS_DWARF",
            0x7000001f => "SHT_MIPS_DELTADECL",
            0x70000020 => "SHT_MIPS_SYMBOL_LIB",
            0x70000021 => "SHT_MIPS_EVENTS",
            0x70000022 => "SHT_MIPS_TRANSLATE",
            0x70000023 => "SHT_MIPS_PIXIE",
            0x70000024 => "SHT_MIPS_XLATE",
            0x70000025 => "SHT_MIPS_XLATE_DEBUG",
            0x70000026 => "SHT_MIPS_WHIRL",
            0x70000027 => "SHT_MIPS_EH_REGION",
            0x70000028 => "SHT_MIPS_XLATE_OLD",
            0x70000029 => "SHT_MIPS_PDR_EXCEPTION",
            _ => "UNKNOWN/MIPS_VENDOR",
        }
    }

    /* Legal values for sh_flags (section flags).  */

        // #define SHF_WRITE             (1 << 0)        /* Writable */
        // #define SHF_ALLOC             (1 << 1)        /* Occupies memory during execution */
        // #define SHF_EXECINSTR             (1 << 2)        /* Executable */
        // #define SHF_MERGE             (1 << 4)        /* Might be merged */
        // #define SHF_STRINGS             (1 << 5)        /* Contains nul-terminated strings */
        // #define SHF_INFO_LINK             (1 << 6)        /* `sh_info' contains SHT index */
        // #define SHF_LINK_ORDER             (1 << 7)        /* Preserve order after combining */
        // #define SHF_OS_NONCONFORMING (1 << 8)        /* Non-standard OS specific handling
        //                                            required */
    // #define SHF_GROUP             (1 << 9)        /* Section is member of a group.  */
    // #define SHF_TLS                     (1 << 10)        /* Section hold thread-local data.  */
    // #define SHF_MASKOS             0x0ff00000        /* OS-specific.  */
    // #define SHF_MASKPROC             0xf0000000        /* Processor-specific */
    // #define SHF_ORDERED             (1 << 30)        /* Special ordering requirement
    //                                            (Solaris).  */
    // #define SHF_EXCLUDE             (1 << 31)        /* Section is excluded unless
    //                                            referenced or allocated (Solaris).*/
    pub fn get_flags_string(&self) -> String {
        let mut flags = Vec::new();
        
        if self.sh_flags & 0x1 != 0 {
            flags.push("SHF_WRITE");
        }
        if self.sh_flags & 0x2 != 0 {
            flags.push("SHF_ALLOC");
        }
        if self.sh_flags & 0x4 != 0 {
            flags.push("SHF_EXECINSTR");
        }
        if self.sh_flags & 0x10 != 0 {
            flags.push("SHF_MERGE");
        }
        if self.sh_flags & 0x20 != 0 {
            flags.push("SHF_STRINGS");
        }
        if self.sh_flags & 0x40 != 0 {
            flags.push("SHF_INFO_LINK");
        }
        if self.sh_flags & 0x80 != 0 {
            flags.push("SHF_LINK_ORDER");
        }
        if self.sh_flags & 0x100 != 0 {
            flags.push("SHF_OS_NONCONFORMING");
        }
        if self.sh_flags & 0x200 != 0 {
            flags.push("SHF_GROUP");
        }
        if self.sh_flags & 0x400 != 0 {
            flags.push("SHF_TLS");
        }
        if self.sh_flags & 0x40000000 != 0 {
            flags.push("SHF_ORDERED");
        }
        if self.sh_flags & 0x80000000 != 0 {
            flags.push("SHF_EXCLUDE");
        }
        
        if flags.is_empty() {
            "".to_string()
        } else {
            flags.join(", ")
        }
    }


    pub fn print(&self, index: usize, bytes: &[u8]) {
        println!("Section Header {}:", index);
        println!("  Name: {}", self.sh_name);
        let type_name = self.get_type_name();
        println!("  Type: {}", type_name);
        println!("  Flags: {} (0x{:016X})", self.get_flags_string(), self.sh_flags);
        println!("  Address: 0x{:016X}", self.sh_addr);
        println!("  Offset: 0x{:016X}", self.sh_offset);
        println!("  Size: 0x{:016X}", self.sh_size);
        
        if type_name == "SHT_SYMTAB" || type_name == "SHT_DYNSYM" {
            if self.sh_entsize > 0 && self.sh_size > 0 {
                let num_symbols = (self.sh_size / self.sh_entsize) as usize;
                println!("  Symbols ({} entries):", num_symbols);
                for i in 0..num_symbols {
                    let offset = self.sh_offset as usize + (i * self.sh_entsize as usize);
                    if offset + 24 <= bytes.len() {
                        let sym = crate::elf_symbol::Elf64_Sym::read_bytes(bytes, offset);
                        println!("    Symbol {}:", i);
                        sym.print();
                    }
                }
            }
        }
        
        if type_name == "SHT_RELA" {
            if self.sh_entsize > 0 && self.sh_size > 0 {
                let num_entries = (self.sh_size / self.sh_entsize) as usize;
                println!("  Relocations with addends ({} entries):", num_entries);
                for i in 0..num_entries {
                    let offset = self.sh_offset as usize + (i * self.sh_entsize as usize);
                    if offset + 24 <= bytes.len() {
                        let rela = crate::elf_relocation::Elf64_Rela::read_bytes(bytes, offset);
                        println!("    Relocation {}:", i);
                        rela.print();
                    }
                }
            }
        }
        
        if type_name == "SHT_REL" {
            if self.sh_entsize > 0 && self.sh_size > 0 {
                let num_entries = (self.sh_size / self.sh_entsize) as usize;
                println!("  Relocations ({} entries):", num_entries);
                for i in 0..num_entries {
                    let offset = self.sh_offset as usize + (i * self.sh_entsize as usize);
                    if offset + 16 <= bytes.len() {
                        let rel = crate::elf_relocation::Elf64_Rel::read_bytes(bytes, offset);
                        println!("    Relocation {}:", i);
                        rel.print();
                    }
                }
            }
        }
        
        if type_name == "SHT_DYNAMIC" {
            if self.sh_entsize > 0 && self.sh_size > 0 {
                let num_entries = (self.sh_size / self.sh_entsize) as usize;
                println!("  Dynamic entries ({} entries):", num_entries);
                for i in 0..num_entries {
                    let offset = self.sh_offset as usize + (i * self.sh_entsize as usize);
                    if offset + 16 <= bytes.len() {
                        let dyn_entry = crate::elf_dynamic::Elf64_Dyn::read_bytes(bytes, offset);
                        println!("    Dynamic {}:", i);
                        dyn_entry.print();
                        if dyn_entry.d_tag == 0 {
                            break;
                        }
                    }
                }
            }
        }
        
        if type_name == "SHT_NOTE" {
            if self.sh_size > 0 {
                let offset = self.sh_offset as usize;
                if offset + 12 <= bytes.len() {
                    let note = crate::elf_notes::Elf64_Nhdr::read_bytes(bytes, offset);
                    println!("  Note:");
                    note.print(bytes, offset);
                }
            }
        }
    }
}

