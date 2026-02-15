#![allow(non_camel_case_types)]

pub struct Elf32_Nhdr {
    pub n_namesz: u32,
    pub n_descsz: u32,
    pub n_type: u32,
}

pub struct Elf64_Nhdr {
    pub n_namesz: u32,
    pub n_descsz: u32,
    pub n_type: u32,
}

fn get_note_type_name(n_type: u32, name: &str) -> String {
    if name == "GNU" {
        match n_type {
            1 => "NT_GNU_ABI_TAG".to_string(),
            2 => "NT_GNU_HWCAP".to_string(),
            3 => "NT_GNU_BUILD_ID".to_string(),
            4 => "NT_GNU_GOLD_VERSION".to_string(),
            _ => format!("NT_UNKNOWN({})", n_type),
        }
    } else {
        match n_type {
            1 => "NT_PRSTATUS".to_string(),
            2 => "NT_FPREGSET".to_string(),
            3 => "NT_PRPSINFO".to_string(),
            4 => "NT_PRXREG".to_string(),
            5 => "NT_PLATFORM".to_string(),
            6 => "NT_AUXV".to_string(),
            7 => "NT_GWINDOWS".to_string(),
            8 => "NT_ASRS".to_string(),
            10 => "NT_PSTATUS".to_string(),
            13 => "NT_PSINFO".to_string(),
            14 => "NT_PRCRED".to_string(),
            15 => "NT_UTSNAME".to_string(),
            16 => "NT_LWPSTATUS".to_string(),
            17 => "NT_LWPSINFO".to_string(),
            20 => "NT_PRFPXREG".to_string(),
            0x46e62b7f => "NT_PRXFPREG".to_string(),
            0x100 => "NT_PPC_VMX".to_string(),
            0x101 => "NT_PPC_SPE".to_string(),
            0x102 => "NT_PPC_VSX".to_string(),
            0x200 => "NT_386_TLS".to_string(),
            0x201 => "NT_386_IOPERM".to_string(),
            _ => format!("NT_UNKNOWN({})", n_type),
        }
    }
}

impl Elf32_Nhdr {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let n_namesz = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let n_descsz = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        let n_type = u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap());
        Self {
            n_namesz,
            n_descsz,
            n_type,
        }
    }

    pub fn print(&self, bytes: &[u8], offset: usize) {
        let name_offset = offset + 12;
        let mut name = String::new();

        if self.n_namesz > 0 && name_offset + self.n_namesz as usize <= bytes.len() {
            for i in 0..self.n_namesz as usize {
                let byte = bytes[name_offset + i];
                if byte == 0 {
                    break;
                }
                name.push(byte as char);
            }
        }

        println!("    Name size: {}", self.n_namesz);
        println!("    Desc size: {}", self.n_descsz);
        println!(
            "    Type: {} ({})",
            get_note_type_name(self.n_type, &name),
            self.n_type
        );
        if !name.is_empty() {
            println!("    Name: {}", name);
        }
    }
}

impl Elf64_Nhdr {
    pub fn read_bytes(bytes: &[u8], offset: usize) -> Self {
        let n_namesz = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let n_descsz = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        let n_type = u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap());
        Self {
            n_namesz,
            n_descsz,
            n_type,
        }
    }

    pub fn print(&self, bytes: &[u8], offset: usize) {
        let name_offset = offset + 12;
        let mut name = String::new();

        if self.n_namesz > 0 && name_offset + self.n_namesz as usize <= bytes.len() {
            for i in 0..self.n_namesz as usize {
                let byte = bytes[name_offset + i];
                if byte == 0 {
                    break;
                }
                name.push(byte as char);
            }
        }

        println!("    Name size: {}", self.n_namesz);
        println!("    Desc size: {}", self.n_descsz);
        println!(
            "    Type: {} ({})",
            get_note_type_name(self.n_type, &name),
            self.n_type
        );
        if !name.is_empty() {
            println!("    Name: {}", name);
        }
    }
}
