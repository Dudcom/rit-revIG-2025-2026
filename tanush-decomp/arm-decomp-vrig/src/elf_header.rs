
// https://man7.org/linux/man-pages/man5/elf.5.html
// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html#elfid
// https://sites.uclouvain.be/SystInfo/usr/include/elf.h.html
use crate::elf_sectionheaders::{Elf32_Shdr, Elf64_Shdr};

pub type ElfNAddr = u64;
pub type ElfNOff = u64;
pub type ElfNSection = u16;
pub type ElfNVersym = u16;
pub type ElfByte = u8;
pub type ElfNHalf = u16;
pub type ElfNSWord = i32;
pub type ElfNWord = u32;
pub type ElfNSXWord = i64;
pub type ElfNXWord = u64;


#[derive(Clone, Copy, PartialEq)]
pub enum ElfFileType {
    NONE,
    REL,
    EXEC,
    DYN,
    CORE,
    LOOS,
    HISOS,
    LOPROC,
    HIPROC,
    Unknown(u16),
}

impl ElfFileType {
    pub fn from_raw(v: u16) -> Self {
        match v {
            0 => ElfFileType::NONE,
            1 => ElfFileType::REL,
            2 => ElfFileType::EXEC,
            3 => ElfFileType::DYN,
            4 => ElfFileType::CORE,
            x if (0xfe00..=0xfeff).contains(&x) => ElfFileType::LOOS,
            x if (0xff00..=0xffff).contains(&x) => ElfFileType::LOPROC,
            x => ElfFileType::Unknown(x),
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            ElfFileType::NONE => "No file type",
            ElfFileType::REL => "Relocatable file",
            ElfFileType::EXEC => "Executable file",
            ElfFileType::DYN => "Shared object file",
            ElfFileType::CORE => "Core file",
            ElfFileType::LOOS => "Operating system-specific",
            ElfFileType::HISOS => "Operating system-specific",
            ElfFileType::LOPROC | ElfFileType::HIPROC => "Processor-specific",
            ElfFileType::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum ElfClass {
    NONE,
    CLASS32,
    CLASS64,
    Unknown(u8),
}

impl ElfClass {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => ElfClass::NONE,
            1 => ElfClass::CLASS32,
            2 => ElfClass::CLASS64,
            x => ElfClass::Unknown(x),
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            ElfClass::NONE => "Invalid Class",
            ElfClass::CLASS32 => "32-bit",
            ElfClass::CLASS64 => "64-bit",
            ElfClass::Unknown(_) => "Invalid Class",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum ElfData {
    NONE,
    DATA2LSB,
    DATA2MSB,
    Unknown(u8),
}

impl ElfData {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => ElfData::NONE,
            1 => ElfData::DATA2LSB,
            2 => ElfData::DATA2MSB,
            x => ElfData::Unknown(x),
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            ElfData::NONE => "Invalid Data Encoding",
            ElfData::DATA2LSB => "Little Endian",
            ElfData::DATA2MSB => "Big Endian",
            ElfData::Unknown(_) => "Invalid Data Encoding",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum ElfVersion {
    NONE,
    CURRENT,
    Unknown(u8),
}

impl ElfVersion {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => ElfVersion::NONE,
            1 => ElfVersion::CURRENT,
            x => ElfVersion::Unknown(x),
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            ElfVersion::NONE => "Invalid Version",
            ElfVersion::CURRENT => "Current",
            ElfVersion::Unknown(_) => "Invalid Version",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum ElfOSABI {
    NONE,
    HPUX,
    NETBSD,
    LINUX,
    SOLARIS,
    AIX,
    IRIX,
    FREEBSD,
    TRU64,
    MODESTO,
    OPENBSD,
    OPENVMS,
    NSK,
    ARM,
    STANDALONE,
    Unknown(u8),
}

impl ElfOSABI {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => ElfOSABI::NONE,
            1 => ElfOSABI::HPUX,
            2 => ElfOSABI::NETBSD,
            3 => ElfOSABI::LINUX,
            6 => ElfOSABI::SOLARIS,
            7 => ElfOSABI::AIX,
            8 => ElfOSABI::IRIX,
            9 => ElfOSABI::FREEBSD,
            10 => ElfOSABI::TRU64,
            11 => ElfOSABI::MODESTO,
            12 => ElfOSABI::OPENBSD,
            13 => ElfOSABI::OPENVMS,
            14 => ElfOSABI::NSK,
            97 => ElfOSABI::ARM,
            255 => ElfOSABI::STANDALONE,
            x => ElfOSABI::Unknown(x),
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            ElfOSABI::NONE => "No extensions or unspecified",
            ElfOSABI::HPUX => "Hewlett-Packard HP-UX",
            ElfOSABI::NETBSD => "NetBSD",
            ElfOSABI::LINUX => "Linux",
            ElfOSABI::SOLARIS => "Sun Solaris",
            ElfOSABI::AIX => "AIX",
            ElfOSABI::IRIX => "IRIX",
            ElfOSABI::FREEBSD => "FreeBSD",
            ElfOSABI::TRU64 => "TRU64 UNIX",
            ElfOSABI::MODESTO => "Novell Modesto",
            ElfOSABI::OPENBSD => "Open BSD",
            ElfOSABI::OPENVMS => "Open VMS",
            ElfOSABI::NSK => "Hewlett-Packard Non-Stop Kernel",
            ElfOSABI::ARM => "ARM architecture",
            ElfOSABI::STANDALONE => "Stand-alone (embedded)",
            ElfOSABI::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum EMMachine {
    EM_NONE,
    EM_M32,
    EM_SPARC,
    EM_386,
    EM_68K,
    EM_88K,
    EM_860,
    EM_MIPS,
    EM_S370,
    EM_MIPS_RS3_LE,
    EM_PARISC,
    EM_VPP500,
    EM_SPARC32PLUS,
    EM_960,
    EM_PPC,
    EM_PPC64,
    EM_S390,
    EM_V800,
    EM_FR20,
    EM_RH32,
    EM_RCE,
    EM_ARM,
    EM_ALPHA,
    EM_SH,
    EM_SPARCV9,
    EM_TRICORE,
    EM_ARC,
    EM_H8_300,
    EM_H8_300H,
    EM_H8S,
    EM_H8_500,
    EM_IA_64,
    EM_MIPS_X,
    EM_COLDFIRE,
    EM_68HC12,
    EM_MMA,
    EM_PCP,
    EM_NCPU,
    EM_NDR1,
    EM_STARCORE,
    EM_ME16,
    EM_ST100,
    EM_TINYJ,
    EM_X86_64,
    EM_PDSP,
    EM_PDP10,
    EM_PDP11,
    EM_FX66,
    EM_ST9PLUS,
    EM_ST7,
    EM_68HC16,
    EM_68HC11,
    EM_68HC08,
    EM_68HC05,
    EM_SVX,
    EM_ST19,
    EM_VAX,
    EM_CRIS,
    EM_JAVELIN,
    EM_FIREPATH,
    EM_ZSP,
    EM_MMIX,
    EM_HUANY,
    EM_PRISM,
    EM_AVR,
    EM_FR30,
    EM_D10V,
    EM_D30V,
    EM_V850,
    EM_M32R,
    EM_MN10300,
    EM_MN10200,
    EM_PJ,
    EM_OPENRISC,
    EM_ARC_A5,
    EM_XTENSA,
    EM_VIDEOCORE,
    EM_TMM_GPP,
    EM_NS32K,
    EM_TPC,
    EM_SNP1K,
    EM_ST200,
    Unknown(u16),
}

impl EMMachine {
    pub fn from_raw(v: u16) -> Self {
        match v {
            0 => EMMachine::EM_NONE,
            1 => EMMachine::EM_M32,
            2 => EMMachine::EM_SPARC,
            3 => EMMachine::EM_386,
            4 => EMMachine::EM_68K,
            5 => EMMachine::EM_88K,
            7 => EMMachine::EM_860,
            8 => EMMachine::EM_MIPS,
            9 => EMMachine::EM_S370,
            10 => EMMachine::EM_MIPS_RS3_LE,
            15 => EMMachine::EM_PARISC,
            17 => EMMachine::EM_VPP500,
            18 => EMMachine::EM_SPARC32PLUS,
            19 => EMMachine::EM_960,
            20 => EMMachine::EM_PPC,
            21 => EMMachine::EM_PPC64,
            22 => EMMachine::EM_S390,
            36 => EMMachine::EM_V800,
            37 => EMMachine::EM_FR20,
            38 => EMMachine::EM_RH32,
            39 => EMMachine::EM_RCE,
            40 => EMMachine::EM_ARM,
            41 => EMMachine::EM_ALPHA,
            42 => EMMachine::EM_SH,
            43 => EMMachine::EM_SPARCV9,
            44 => EMMachine::EM_TRICORE,
            45 => EMMachine::EM_ARC,
            46 => EMMachine::EM_H8_300,
            47 => EMMachine::EM_H8_300H,
            48 => EMMachine::EM_H8S,
            49 => EMMachine::EM_H8_500,
            50 => EMMachine::EM_IA_64,
            51 => EMMachine::EM_MIPS_X,
            52 => EMMachine::EM_COLDFIRE,
            53 => EMMachine::EM_68HC12,
            54 => EMMachine::EM_MMA,
            55 => EMMachine::EM_PCP,
            56 => EMMachine::EM_NCPU,
            57 => EMMachine::EM_NDR1,
            58 => EMMachine::EM_STARCORE,
            59 => EMMachine::EM_ME16,
            60 => EMMachine::EM_ST100,
            61 => EMMachine::EM_TINYJ,
            62 => EMMachine::EM_X86_64,
            63 => EMMachine::EM_PDSP,
            64 => EMMachine::EM_PDP10,
            65 => EMMachine::EM_PDP11,
            66 => EMMachine::EM_FX66,
            67 => EMMachine::EM_ST9PLUS,
            68 => EMMachine::EM_ST7,
            69 => EMMachine::EM_68HC16,
            70 => EMMachine::EM_68HC11,
            71 => EMMachine::EM_68HC08,
            72 => EMMachine::EM_68HC05,
            73 => EMMachine::EM_SVX,
            74 => EMMachine::EM_ST19,
            75 => EMMachine::EM_VAX,
            76 => EMMachine::EM_CRIS,
            77 => EMMachine::EM_JAVELIN,
            78 => EMMachine::EM_FIREPATH,
            79 => EMMachine::EM_ZSP,
            80 => EMMachine::EM_MMIX,
            81 => EMMachine::EM_HUANY,
            82 => EMMachine::EM_PRISM,
            83 => EMMachine::EM_AVR,
            84 => EMMachine::EM_FR30,
            85 => EMMachine::EM_D10V,
            86 => EMMachine::EM_D30V,
            87 => EMMachine::EM_V850,
            88 => EMMachine::EM_M32R,
            89 => EMMachine::EM_MN10300,
            90 => EMMachine::EM_MN10200,
            91 => EMMachine::EM_PJ,
            92 => EMMachine::EM_OPENRISC,
            93 => EMMachine::EM_ARC_A5,
            94 => EMMachine::EM_XTENSA,
            95 => EMMachine::EM_VIDEOCORE,
            96 => EMMachine::EM_TMM_GPP,
            97 => EMMachine::EM_NS32K,
            98 => EMMachine::EM_TPC,
            99 => EMMachine::EM_SNP1K,
            100 => EMMachine::EM_ST200,
            x => EMMachine::Unknown(x),
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            EMMachine::EM_NONE => "None",
            EMMachine::EM_M32 => "AT&T WE 32100",
            EMMachine::EM_SPARC => "SPARC",
            EMMachine::EM_386 => "Intel 80386",
            EMMachine::EM_68K => "Motorola 68000",
            EMMachine::EM_88K => "Motorola 88000",
            EMMachine::EM_860 => "Intel 80860",
            EMMachine::EM_MIPS => "MIPS I Architecture",
            EMMachine::EM_S370 => "IBM System/370 Processor",
            EMMachine::EM_MIPS_RS3_LE => "MIPS RS3000 Little-endian",
            EMMachine::EM_PARISC => "Hewlett-Packard PA-RISC",
            EMMachine::EM_VPP500 => "Fujitsu VPP500",
            EMMachine::EM_SPARC32PLUS => "Enhanced instruction set SPARC",
            EMMachine::EM_960 => "Intel 80960",
            EMMachine::EM_PPC => "PowerPC",
            EMMachine::EM_PPC64 => "64-bit PowerPC",
            EMMachine::EM_S390 => "IBM System/390 Processor",
            EMMachine::EM_V800 => "NEC V800",
            EMMachine::EM_FR20 => "Fujitsu FR20",
            EMMachine::EM_RH32 => "TRW RH-32",
            EMMachine::EM_RCE => "Motorola RCE",
            EMMachine::EM_ARM => "Advanced RISC Machines ARM",
            EMMachine::EM_ALPHA => "Digital Alpha",
            EMMachine::EM_SH => "Hitachi SH",
            EMMachine::EM_SPARCV9 => "SPARC Version 9",
            EMMachine::EM_TRICORE => "Siemens TriCore embedded processor",
            EMMachine::EM_ARC => "Argonaut RISC Core",
            EMMachine::EM_H8_300 => "Hitachi H8/300",
            EMMachine::EM_H8_300H => "Hitachi H8/300H",
            EMMachine::EM_H8S => "Hitachi H8S",
            EMMachine::EM_H8_500 => "Hitachi H8/500",
            EMMachine::EM_IA_64 => "Intel IA-64 processor architecture",
            EMMachine::EM_MIPS_X => "Stanford MIPS-X",
            EMMachine::EM_COLDFIRE => "Motorola ColdFire",
            EMMachine::EM_68HC12 => "Motorola M68HC12",
            EMMachine::EM_MMA => "Fujitsu MMA Multimedia Accelerator",
            EMMachine::EM_PCP => "Siemens PCP",
            EMMachine::EM_NCPU => "Sony nCPU embedded RISC processor",
            EMMachine::EM_NDR1 => "Denso NDR1 microprocessor",
            EMMachine::EM_STARCORE => "Motorola Star*Core processor",
            EMMachine::EM_ME16 => "Toyota ME16 processor",
            EMMachine::EM_ST100 => "STMicroelectronics ST100 processor",
            EMMachine::EM_TINYJ => "Advanced Logic Corp. TinyJ processor family",
            EMMachine::EM_X86_64 => "AMD x86-64 architecture",
            EMMachine::EM_PDSP => "Sony DSP Processor",
            EMMachine::EM_PDP10 => "Digital Equipment Corp. PDP-10",
            EMMachine::EM_PDP11 => "Digital Equipment Corp. PDP-11",
            EMMachine::EM_FX66 => "Siemens FX66 microcontroller",
            EMMachine::EM_ST9PLUS => "STMicroelectronics ST9+ 8/16 bit microcontroller",
            EMMachine::EM_ST7 => "STMicroelectronics ST7 8-bit microcontroller",
            EMMachine::EM_68HC16 => "Motorola MC68HC16 Microcontroller",
            EMMachine::EM_68HC11 => "Motorola MC68HC11 Microcontroller",
            EMMachine::EM_68HC08 => "Motorola MC68HC08 Microcontroller",
            EMMachine::EM_68HC05 => "Motorola MC68HC05 Microcontroller",
            EMMachine::EM_SVX => "Silicon Graphics SVx",
            EMMachine::EM_ST19 => "STMicroelectronics ST19 8-bit microcontroller",
            EMMachine::EM_VAX => "Digital VAX",
            EMMachine::EM_CRIS => "Axis Communications 32-bit embedded processor",
            EMMachine::EM_JAVELIN => "Infineon Technologies 32-bit embedded processor",
            EMMachine::EM_FIREPATH => "Element 14 64-bit DSP Processor",
            EMMachine::EM_ZSP => "LSI Logic 16-bit DSP Processor",
            EMMachine::EM_MMIX => "Donald Knuth's educational 64-bit processor",
            EMMachine::EM_HUANY => "Harvard University object files",
            EMMachine::EM_PRISM => "SiTera Prism",
            EMMachine::EM_AVR => "Atmel AVR 8-bit microcontroller",
            EMMachine::EM_FR30 => "Fujitsu FR30",
            EMMachine::EM_D10V => "Mitsubishi D10V",
            EMMachine::EM_D30V => "Mitsubishi D30V",
            EMMachine::EM_V850 => "NEC v850",
            EMMachine::EM_M32R => "Mitsubishi M32R",
            EMMachine::EM_MN10300 => "Matsushita MN10300",
            EMMachine::EM_MN10200 => "Matsushita MN10200",
            EMMachine::EM_PJ => "picoJava",
            EMMachine::EM_OPENRISC => "OpenRISC 32-bit embedded processor",
            EMMachine::EM_ARC_A5 => "ARC Cores Tangent-A5",
            EMMachine::EM_XTENSA => "Tensilica Xtensa Architecture",
            EMMachine::EM_VIDEOCORE => "Alphamosaic VideoCore processor",
            EMMachine::EM_TMM_GPP => "Thompson Multimedia General Purpose Processor",
            EMMachine::EM_NS32K => "National Semiconductor 32000 series",
            EMMachine::EM_TPC => "Tenor Network TPC processor",
            EMMachine::EM_SNP1K => "Trebia SNP 1000 processor",
            EMMachine::EM_ST200 => "STMicroelectronics ST200 microcontroller",
            EMMachine::Unknown(_) => "Invalid Machine Type",
        }
    }
}




// /* Processor specific flags for the ELF header e_flags field.  */
// #define EF_ARM_RELEXEC                0x01
// #define EF_ARM_HASENTRY                0x02
// #define EF_ARM_INTERWORK        0x04
// #define EF_ARM_APCS_26                0x08
// #define EF_ARM_APCS_FLOAT        0x10
// #define EF_ARM_PIC                0x20
// #define EF_ARM_ALIGN8                0x40 /* 8-bit structure alignment is in use */
// #define EF_ARM_NEW_ABI                0x80
// #define EF_ARM_OLD_ABI                0x100
// #define EF_ARM_SOFT_FLOAT        0x200
// #define EF_ARM_VFP_FLOAT        0x400
// #define EF_ARM_MAVERICK_FLOAT        0x800

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum ElfFlagsARM {
    EF_ARM_RELEXEC = 0x01,
    EF_ARM_HASENTRY = 0x02,
    EF_ARM_INTERWORK = 0x04,
    EF_ARM_APCS_26 = 0x08,
    EF_ARM_APCS_FLOAT = 0x10,
    EF_ARM_PIC = 0x20,
    EF_ARM_ALIGN8 = 0x40,
    EF_ARM_NEW_ABI = 0x80,
    EF_ARM_OLD_ABI = 0x100,
    EF_ARM_SOFT_FLOAT = 0x200,
    EF_ARM_VFP_FLOAT = 0x400,
    EF_ARM_MAVERICK_FLOAT = 0x800,
}


pub const EI_NIDENT: usize = 16;

pub struct ElfNEhdr {
    pub e_ident: [u8; EI_NIDENT],
    pub class: ElfClass,
    pub data: ElfData,
    pub version_ident: ElfVersion,
    pub osabi: ElfOSABI,
    pub e_type: ElfFileType,
    pub e_machine: EMMachine,
    pub e_version: ElfVersion,
    pub e_entry: ElfNAddr,
    pub e_phoff: ElfNOff,
    pub e_shoff: ElfNOff,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}


pub struct Elf32_Phdr {
    pub p_type: ElfPhdrType,
    pub p_offset: ElfNOff,
    pub p_vaddr: ElfNAddr,
    pub p_paddr: ElfNAddr,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

pub struct Elf64_Phdr {
    pub p_type: ElfPhdrType,
    pub p_flags: u32,
    pub p_offset: ElfNOff,
    pub p_vaddr: ElfNAddr,
    pub p_paddr: ElfNAddr,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}


#[derive(Clone, Copy, PartialEq)]
pub enum ElfPhdrType {
    PT_NULL,
    PT_LOAD,
    PT_DYNAMIC,
    PT_INTERP,
    PT_NOTE,
    PT_SHLIB,
    PT_PHDR,
    PT_TLS,
    PT_NUM,
    PT_LOOS,
    PT_GNU_EH_FRAME,
    PT_GNU_STACK,
    PT_GNU_RELRO,
    PT_LOSUNW,
    PT_SUNWSTACK,
    PT_HISUNW,
    PT_LOPROC,
    PT_HIPROC,
    Unknown(u32),
}

impl ElfPhdrType {
    pub fn from_raw(v: u32) -> Self {
        match v {
            0 => ElfPhdrType::PT_NULL,
            1 => ElfPhdrType::PT_LOAD,
            2 => ElfPhdrType::PT_DYNAMIC,
            3 => ElfPhdrType::PT_INTERP,
            4 => ElfPhdrType::PT_NOTE,
            5 => ElfPhdrType::PT_SHLIB,
            6 => ElfPhdrType::PT_PHDR,
            7 => ElfPhdrType::PT_TLS,
            8 => ElfPhdrType::PT_NUM,
            0x6474e550 => ElfPhdrType::PT_GNU_EH_FRAME,
            0x6474e551 => ElfPhdrType::PT_GNU_STACK,
            0x6474e552 => ElfPhdrType::PT_GNU_RELRO,
            0x6ffffffa => ElfPhdrType::PT_LOSUNW,
            0x6ffffffb => ElfPhdrType::PT_SUNWSTACK,
            0x6fffffff => ElfPhdrType::PT_HISUNW,
            x if (0x60000000..0x6fffffff).contains(&x) => ElfPhdrType::PT_LOOS,
            x if (0x70000000..=0x7fffffff).contains(&x) => ElfPhdrType::PT_LOPROC,
            x => ElfPhdrType::Unknown(x),
        }
    }
    pub fn as_raw(&self) -> u32 {
        match self {
            ElfPhdrType::PT_NULL => 0,
            ElfPhdrType::PT_LOAD => 1,
            ElfPhdrType::PT_DYNAMIC => 2,
            ElfPhdrType::PT_INTERP => 3,
            ElfPhdrType::PT_NOTE => 4,
            ElfPhdrType::PT_SHLIB => 5,
            ElfPhdrType::PT_PHDR => 6,
            ElfPhdrType::PT_TLS => 7,
            ElfPhdrType::PT_NUM => 8,
            ElfPhdrType::PT_GNU_EH_FRAME => 0x6474e550,
            ElfPhdrType::PT_GNU_STACK => 0x6474e551,
            ElfPhdrType::PT_GNU_RELRO => 0x6474e552,
            ElfPhdrType::PT_LOOS => 0x60000000,
            ElfPhdrType::PT_LOSUNW => 0x6ffffffa,
            ElfPhdrType::PT_SUNWSTACK => 0x6ffffffb,
            ElfPhdrType::PT_HISUNW => 0x6fffffff,
            ElfPhdrType::PT_LOPROC => 0x70000000,
            ElfPhdrType::PT_HIPROC => 0x7fffffff,
            ElfPhdrType::Unknown(x) => *x,
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            ElfPhdrType::PT_NULL => "PT_NULL",
            ElfPhdrType::PT_LOAD => "PT_LOAD",
            ElfPhdrType::PT_DYNAMIC => "PT_DYNAMIC",
            ElfPhdrType::PT_INTERP => "PT_INTERP",
            ElfPhdrType::PT_NOTE => "PT_NOTE",
            ElfPhdrType::PT_SHLIB => "PT_SHLIB",
            ElfPhdrType::PT_PHDR => "PT_PHDR",
            ElfPhdrType::PT_TLS => "PT_TLS",
            ElfPhdrType::PT_NUM => "PT_NUM",
            ElfPhdrType::PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME",
            ElfPhdrType::PT_GNU_STACK => "PT_GNU_STACK",
            ElfPhdrType::PT_GNU_RELRO => "PT_GNU_RELRO",
            ElfPhdrType::PT_LOOS => "PT_LOOS (OS-specific)",
            ElfPhdrType::PT_LOSUNW => "PT_LOSUNW",
            ElfPhdrType::PT_SUNWSTACK => "PT_SUNWSTACK",
            ElfPhdrType::PT_HISUNW => "PT_HISUNW",
            ElfPhdrType::PT_LOPROC => "PT_LOPROC (Processor-specific)",
            ElfPhdrType::PT_HIPROC => "PT_HIPROC",
            ElfPhdrType::Unknown(_) => "PT_UNKNOWN",
        }
    }
}

// #define        PT_NULL                0                /* Program header table entry unused */
// #define PT_LOAD                1                /* Loadable program segment */
// #define PT_DYNAMIC        2                /* Dynamic linking information */
// #define PT_INTERP        3                /* Program interpreter */
// #define PT_NOTE                4                /* Auxiliary information */
// #define PT_SHLIB        5                /* Reserved */
// #define PT_PHDR                6                /* Entry for header table itself */
// #define PT_TLS                7                /* Thread-local storage segment */
// #define        PT_NUM                8                /* Number of defined types */
// #define PT_LOOS                0x60000000        /* Start of OS-specific */
// #define PT_GNU_EH_FRAME        0x6474e550        /* GCC .eh_frame_hdr segment */
// #define PT_GNU_STACK        0x6474e551        /* Indicates stack executability */
// #define PT_GNU_RELRO        0x6474e552        /* Read-only after relocation */
// #define PT_LOSUNW        0x6ffffffa
// #define PT_SUNWBSS        0x6ffffffa        /* Sun Specific segment */
// #define PT_SUNWSTACK        0x6ffffffb        /* Stack segment */
// #define PT_HISUNW        0x6fffffff
// #define PT_HIOS                0x6fffffff        /* End of OS-specific */
// #define PT_LOPROC        0x70000000        /* Start of processor-specific */
// #define PT_HIPROC        0x7fffffff        /* End of processor-specific */



impl ElfNEhdr {

    fn validate_elf_header(&self) {
        if self.e_ident[0] != 0x7F ||
           self.e_ident[1] != 0x45 ||
           self.e_ident[2] != 0x4C ||
           self.e_ident[3] != 0x46 {
            println!("ELF file: Magic Number: 0x{:02X}{:02X}{:02X}{:02X}",
                     self.e_ident[0], self.e_ident[1], self.e_ident[2], self.e_ident[3]);
            panic!("Not an ELF file: Invalid Magic Number");
        }
        println!("ELF file: Magic Number: 0x{:02X}{:02X}{:02X}{:02X}",
                 self.e_ident[0], self.e_ident[1], self.e_ident[2], self.e_ident[3]);

        match self.class {
            ElfClass::NONE | ElfClass::Unknown(_) => panic!("Not an ELF file: Invalid Class"),
            ElfClass::CLASS32 => println!("ELF file: Class: 32-bit"),
            ElfClass::CLASS64 => println!("ELF file: Class: 64-bit"),
        }

        match self.data {
            ElfData::NONE | ElfData::Unknown(_) => panic!("Not an ELF file: Invalid Data Encoding"),
            ElfData::DATA2LSB => println!("ELF file: Data Encoding: Little Endian"),
            ElfData::DATA2MSB => println!("ELF file: Data Encoding: Big Endian"),
        }

        match self.version_ident {
            ElfVersion::NONE | ElfVersion::Unknown(_) => panic!("Not an ELF file: Invalid Version"),
            ElfVersion::CURRENT => println!("ELF file: Version: Current"),
        }

        println!("ELF file: OS ABI: {}", self.osabi.type_name());
        println!("ELF file: ABI Version: {}", self.e_ident[8]);

        for i in 0..8 {
            if self.e_ident[i + 8] != 0x00 {
                panic!("Not an ELF file: Invalid Padding");
            }
        }
    }




    fn validate_elf_type(&self) {
        println!("ELF file: Type: {}", self.e_type.type_name());
    }

    fn validate_elf_machine(&self) {
        match self.e_machine {
            EMMachine::Unknown(_) => panic!("Not an ELF file: Invalid Machine Type"),
            _ => println!("ELF file: Machine: {}", self.e_machine.type_name()),
        }
    }

    fn validate_elf_version(&self) {
        match self.e_version {
            ElfVersion::NONE | ElfVersion::Unknown(_) => panic!("Not an ELF file: Invalid Version"),
            ElfVersion::CURRENT => println!("ELF file: Version: Current"),
        }
    }


    // /* Processor specific flags for the ELF header e_flags field.  */
    // #define EF_ARM_RELEXEC                0x01
    // #define EF_ARM_HASENTRY                0x02
    // #define EF_ARM_INTERWORK        0x04
    // #define EF_ARM_APCS_26                0x08
    // #define EF_ARM_APCS_FLOAT        0x10
    // #define EF_ARM_PIC                0x20
    // #define EF_ARM_ALIGN8                0x40 /* 8-bit structure alignment is in use */
    // #define EF_ARM_NEW_ABI                0x80
    // #define EF_ARM_OLD_ABI                0x100
    // #define EF_ARM_SOFT_FLOAT        0x200
    // #define EF_ARM_VFP_FLOAT        0x400
    // #define EF_ARM_MAVERICK_FLOAT        0x800
    fn validate_elf_flags(&self) {
        if self.e_flags & ElfFlagsARM::EF_ARM_RELEXEC as u32 != 0 {
            println!("ELF file: Flags: REL executable");
        }
        if self.e_flags & ElfFlagsARM::EF_ARM_HASENTRY as u32 != 0 {
            println!("ELF file: Flags: HAS entry");
        }
        if self.e_flags & ElfFlagsARM::EF_ARM_INTERWORK as u32 != 0 {
            println!("ELF file: Flags: INTERWORK");
        }
        if self.e_flags & ElfFlagsARM::EF_ARM_APCS_26 as u32 != 0 {
            println!("ELF file: Flags: APCS_26");
        }
        if self.e_flags & ElfFlagsARM::EF_ARM_APCS_FLOAT as u32 != 0 {
            println!("ELF file: Flags: APCS_FLOAT");
        }
        if self.e_flags & ElfFlagsARM::EF_ARM_PIC as u32 != 0 {
            println!("ELF file: Flags: PIC");
        }
        if self.e_flags & ElfFlagsARM::EF_ARM_ALIGN8 as u32 != 0 {
            println!("ELF file: Flags: ALIGN8");
        }
        if self.e_flags & ElfFlagsARM::EF_ARM_NEW_ABI as u32 != 0 {
            println!("ELF file: Flags: NEW_ABI");
        }
        if self.e_flags & ElfFlagsARM::EF_ARM_OLD_ABI as u32 != 0 {
            println!("ELF file: Flags: OLD_ABI");
        }
        if self.e_flags & ElfFlagsARM::EF_ARM_SOFT_FLOAT as u32 != 0 {
            println!("ELF file: Flags: SOFT_FLOAT");
        }
        if self.e_flags & ElfFlagsARM::EF_ARM_VFP_FLOAT as u32 != 0 {
            println!("ELF file: Flags: VFP_FLOAT");
        }
        if self.e_flags & ElfFlagsARM::EF_ARM_MAVERICK_FLOAT as u32 != 0 {
            println!("ELF file: Flags: MAVERICK_FLOAT");
        }
    }

    pub fn new() -> Self {
        Self {
            e_ident: [0; EI_NIDENT],
            class: ElfClass::NONE,
            data: ElfData::NONE,
            version_ident: ElfVersion::NONE,
            osabi: ElfOSABI::NONE,
            e_type: ElfFileType::NONE,
            e_machine: EMMachine::EM_NONE,
            e_version: ElfVersion::NONE,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }

    pub fn read_bytes(&mut self, bytes: &[u8]) -> Self {
        let e_type_raw = u16::from_le_bytes(bytes[EI_NIDENT..EI_NIDENT + 2].try_into().unwrap());
        let e_machine_raw = u16::from_le_bytes(bytes[EI_NIDENT + 2..EI_NIDENT + 4].try_into().unwrap());
        let e_version_raw = u32::from_le_bytes(bytes[EI_NIDENT + 4..EI_NIDENT + 8].try_into().unwrap());
        Self {
            e_ident: bytes[0..EI_NIDENT].try_into().unwrap(),
            class: ElfClass::from_raw(bytes[4]),
            data: ElfData::from_raw(bytes[5]),
            version_ident: ElfVersion::from_raw(bytes[6]),
            osabi: ElfOSABI::from_raw(bytes[7]),
            e_type: ElfFileType::from_raw(e_type_raw),
            e_machine: EMMachine::from_raw(e_machine_raw),
            e_version: ElfVersion::from_raw((e_version_raw & 0xff) as u8),
            e_entry: ElfNAddr::from_le_bytes(bytes[EI_NIDENT + 8..EI_NIDENT + 16].try_into().unwrap()),
            e_phoff: ElfNOff::from_le_bytes(bytes[EI_NIDENT + 16..EI_NIDENT + 24].try_into().unwrap()),
            e_shoff: ElfNOff::from_le_bytes(bytes[EI_NIDENT + 24..EI_NIDENT + 32].try_into().unwrap()),
            e_flags: u32::from_le_bytes(bytes[EI_NIDENT + 32..EI_NIDENT + 36].try_into().unwrap()),
            e_ehsize: u16::from_le_bytes(bytes[EI_NIDENT + 36..EI_NIDENT + 38].try_into().unwrap()),
            e_phentsize: u16::from_le_bytes(bytes[EI_NIDENT + 38..EI_NIDENT + 40].try_into().unwrap()),
            e_phnum: u16::from_le_bytes(bytes[EI_NIDENT + 40..EI_NIDENT + 42].try_into().unwrap()),
            e_shentsize: u16::from_le_bytes(bytes[EI_NIDENT + 42..EI_NIDENT + 44].try_into().unwrap()),
            e_shnum: u16::from_le_bytes(bytes[EI_NIDENT + 44..EI_NIDENT + 46].try_into().unwrap()),
            e_shstrndx: u16::from_le_bytes(bytes[EI_NIDENT + 46..EI_NIDENT + 48].try_into().unwrap()),
        }
    }

    pub fn validate(&self, file_bytes: &[u8]) {
        self.validate_elf_header();
        self.validate_elf_type();
        self.validate_elf_machine();
        self.validate_elf_version();
        println!("ELF file: Start Address: 0x{:016X}", self.e_entry);
        println!("ELF file: Program Header Offset: 0x{:016X}", self.e_phoff);
        println!("ELF file: Section Header Offset: 0x{:016X}", self.e_shoff);
        self.validate_elf_flags();
        println!("ELF file: header size: 0x{:02X}", self.e_ehsize);
        println!("ELF file: program header entrysize: 0x{:02X}", self.e_phentsize);
        println!("ELF file: program header count: 0x{:02X}", self.e_phnum);
        println!("ELF file: section header entrysize: 0x{:02X}", self.e_shentsize);
        println!("ELF file: section header count: 0x{:02X}", self.e_shnum);
        println!("ELF file: section header string table index: 0x{:02X}", self.e_shstrndx);
        println!();

        // program header parsing
        if self.class == ElfClass::CLASS32 {
            let mut program_headers: Vec<Elf32_Phdr> = Vec::new();
            let mut offset = self.e_phoff as usize;
            for i in 0..self.e_phnum as usize {
                let phdr = Elf32_Phdr::read_bytes(file_bytes, offset);
                phdr.print(i);
                program_headers.push(phdr);
                offset += self.e_phentsize as usize;
                if phdr.p_type == ElfPhdrType::PT_LOAD as u32 {
                    Decomplier::decomplier_load_section(phdr.p_vaddr, phdr.p_memsz, phdr.p_filesz);
                }
            }
        } else if self.class == ElfClass::CLASS64 {
            let mut program_headers: Vec<Elf64_Phdr> = Vec::new();
            let mut offset = self.e_phoff as usize;
            for i in 0..self.e_phnum as usize {
                let phdr = Elf64_Phdr::read_bytes(file_bytes, offset);
                phdr.print(i);
                program_headers.push(phdr);
                offset += self.e_phentsize as usize;
                if phdr.p_type == ElfPhdrType::PT_LOAD as u32 {
                    Decomplier::decomplier_load_section(phdr.p_vaddr, phdr.p_memsz, phdr.p_filesz);
                }
            }
        }


        // section header parsing
        if self.class == ElfClass::CLASS32 {
            let mut section_headers: Vec<Elf32_Shdr> = Vec::new();
            let mut offset = self.e_shoff as usize;
            for i in 0..self.e_shnum as usize {
                let shdr = Elf32_Shdr::read_bytes(file_bytes, offset);
                shdr.print(i, file_bytes);
                section_headers.push(shdr);
                offset += self.e_shentsize as usize;d
            }
        } else if self.class == ElfClass::CLASS64 {
            let mut section_headers: Vec<Elf64_Shdr> = Vec::new();
            let mut offset = self.e_shoff as usize;
            for i in 0..self.e_shnum as usize {
                let shdr = Elf64_Shdr::read_bytes(file_bytes, offset);
                shdr.print(i, file_bytes);
                section_headers.push(shdr);
                offset += self.e_shentsize as usize;
            }
        }
    }
}