
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


pub enum ElfFileType {
    NONE = 0,
    REL = 1,
    EXEC = 2,
    DYN = 3,
    CORE = 4,
    LOOS = 0xfe00,
    HISOS = 0xfeff,
    LOPROC = 0xff00,
    HIPROC = 0xffff,
}

pub enum ElfClass {
    NONE = 0,
    CLASS32 = 1,
    CLASS64 = 2,
}

pub enum ElfData {
    NONE = 0,
    DATA2LSB = 1,
    DATA2MSB = 2,
}

pub enum ElfVersion {
    NONE = 0,
    CURRENT = 1,
}

pub enum ElfOSABI {
    NONE = 0,
    HPUX = 1,
    NETBSD = 2,
    LINUX = 3,
    SOLARIS = 6,
    AIX = 7,
    IRIX = 8,
    FREEBSD = 9,
    TRU64 = 10,
    MODESTO = 11,
    OPENBSD = 12,
    OPENVMS = 13,
    NSK = 14,
    ARM = 97,
    STANDALONE = 255,
}

pub enum EMMachine {
    EM_NONE = 0,      // No machine
    EM_M32 = 1,       // AT&T WE 32100
    EM_SPARC = 2,     // SPARC
    EM_386 = 3,       // Intel 80386
    EM_68K = 4,       // Motorola 68000
    EM_88K = 5,       // Motorola 88000
    // 6 reserved (was EM_486)
    EM_860 = 7,       // Intel 80860
    EM_MIPS = 8,      // MIPS I Architecture
    EM_S370 = 9,      // IBM System/370 Processor
    EM_MIPS_RS3_LE = 10,  // MIPS RS3000 Little-endian
    // 11-14 reserved
    EM_PARISC = 15,   // Hewlett-Packard PA-RISC
    // 16 reserved
    EM_VPP500 = 17,   // Fujitsu VPP500
    EM_SPARC32PLUS = 18, // Enhanced instruction set SPARC
    EM_960 = 19,      // Intel 80960
    EM_PPC = 20,      // PowerPC
    EM_PPC64 = 21,    // 64-bit PowerPC
    EM_S390 = 22,     // IBM System/390 Processor
    // 23-35 reserved
    EM_V800 = 36,     // NEC V800
    EM_FR20 = 37,     // Fujitsu FR20
    EM_RH32 = 38,     // TRW RH-32
    EM_RCE = 39,      // Motorola RCE
    EM_ARM = 40,      // Advanced RISC Machines ARM
    EM_ALPHA = 41,    // Digital Alpha
    EM_SH = 42,       // Hitachi SH
    EM_SPARCV9 = 43,  // SPARC Version 9
    EM_TRICORE = 44,  // Siemens TriCore embedded processor
    EM_ARC = 45,      // Argonaut RISC Core
    EM_H8_300 = 46,   // Hitachi H8/300
    EM_H8_300H = 47,  // Hitachi H8/300H
    EM_H8S = 48,      // Hitachi H8S
    EM_H8_500 = 49,   // Hitachi H8/500
    EM_IA_64 = 50,    // Intel IA-64 processor architecture
    EM_MIPS_X = 51,   // Stanford MIPS-X
    EM_COLDFIRE = 52, // Motorola ColdFire
    EM_68HC12 = 53,   // Motorola M68HC12
    EM_MMA = 54,      // Fujitsu MMA Multimedia Accelerator
    EM_PCP = 55,      // Siemens PCP
    EM_NCPU = 56,     // Sony nCPU embedded RISC processor
    EM_NDR1 = 57,     // Denso NDR1 microprocessor
    EM_STARCORE = 58, // Motorola Star*Core processor
    EM_ME16 = 59,     // Toyota ME16 processor
    EM_ST100 = 60,    // STMicroelectronics ST100 processor
    EM_TINYJ = 61,    // Advanced Logic Corp. TinyJ processor family
    EM_X86_64 = 62,   // AMD x86-64 architecture
    EM_PDSP = 63,     // Sony DSP Processor
    EM_PDP10 = 64,    // Digital Equipment Corp. PDP-10
    EM_PDP11 = 65,    // Digital Equipment Corp. PDP-11
    EM_FX66 = 66,     // Siemens FX66 microcontroller
    EM_ST9PLUS = 67,  // STMicroelectronics ST9+ 8/16 bit microcontroller
    EM_ST7 = 68,      // STMicroelectronics ST7 8-bit microcontroller
    EM_68HC16 = 69,   // Motorola MC68HC16 Microcontroller
    EM_68HC11 = 70,   // Motorola MC68HC11 Microcontroller
    EM_68HC08 = 71,   // Motorola MC68HC08 Microcontroller
    EM_68HC05 = 72,   // Motorola MC68HC05 Microcontroller
    EM_SVX = 73,      // Silicon Graphics SVx
    EM_ST19 = 74,     // STMicroelectronics ST19 8-bit microcontroller
    EM_VAX = 75,      // Digital VAX
    EM_CRIS = 76,     // Axis Communications 32-bit embedded processor
    EM_JAVELIN = 77,  // Infineon Technologies 32-bit embedded processor
    EM_FIREPATH = 78, // Element 14 64-bit DSP Processor
    EM_ZSP = 79,      // LSI Logic 16-bit DSP Processor
    EM_MMIX = 80,     // Donald Knuth's educational 64-bit processor
    EM_HUANY = 81,    // Harvard University object files
    EM_PRISM = 82,    // SiTera Prism
    EM_AVR = 83,      // Atmel AVR 8-bit microcontroller
    EM_FR30 = 84,     // Fujitsu FR30
    EM_D10V = 85,     // Mitsubishi D10V
    EM_D30V = 86,     // Mitsubishi D30V
    EM_V850 = 87,     // NEC v850
    EM_M32R = 88,     // Mitsubishi M32R
    EM_MN10300 = 89,  // Matsushita MN10300
    EM_MN10200 = 90,  // Matsushita MN10200
    EM_PJ = 91,       // picoJava
    EM_OPENRISC = 92, // OpenRISC 32-bit embedded processor
    EM_ARC_A5 = 93,   // ARC Cores Tangent-A5
    EM_XTENSA = 94,   // Tensilica Xtensa Architecture
    EM_VIDEOCORE = 95,// Alphamosaic VideoCore processor
    EM_TMM_GPP = 96,  // Thompson Multimedia General Purpose Processor
    EM_NS32K = 97,    // National Semiconductor 32000 series
    EM_TPC = 98,      // Tenor Network TPC processor
    EM_SNP1K = 99,    // Trebia SNP 1000 processor
    EM_ST200 = 100,   // STMicroelectronics ST200 microcontroller
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

pub struct ElfNEhdr{
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
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
    pub p_type: u32,
    pub p_offset: ElfNOff,
    pub p_vaddr: ElfNAddr,
    pub p_paddr: ElfNAddr,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

pub struct Elf64_Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: ElfNOff,
    pub p_vaddr: ElfNAddr,
    pub p_paddr: ElfNAddr,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}


pub enum ElfPhdrType {
    PT_NULL = 0,
    PT_LOAD = 1,
    PT_DYNAMIC = 2,
    PT_INTERP = 3,
    PT_NOTE = 4,
    PT_SHLIB = 5,
    PT_PHDR = 6,
    PT_TLS = 7,
    PT_NUM = 8,
    PT_LOOS = 0x60000000,
    PT_GNU_EH_FRAME = 0x6474e550,
    PT_GNU_STACK = 0x6474e551,
    PT_GNU_RELRO = 0x6474e552,
    PT_LOSUNW = 0x6ffffffa,
    PT_SUNWSTACK = 0x6ffffffb,
    PT_HISUNW = 0x6fffffff,
    PT_LOPROC = 0x70000000,
    PT_HIPROC = 0x7fffffff,
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

        match self.e_ident[4] {
            0 => panic!("Not an ELF file: Invalid Class"),
            1 => println!("ELF file: Class: 32-bit"),
            2 => println!("ELF file: Class: 64-bit"),
            _ => panic!("Not an ELF file: Invalid Class"),
        }

        match self.e_ident[5] {
            0 => panic!("Not an ELF file: Invalid Data Encoding"),
            1 => println!("ELF file: Data Encoding: Little Endian"),
            2 => println!("ELF file: Data Encoding: Big Endian"),
            _ => panic!("Not an ELF file: Invalid Data Encoding"),
        }

        match self.e_ident[6] {
            0 => panic!("Not an ELF file: Invalid Version"),
            1 => println!("ELF file: Version: Current"),
            _ => panic!("Not an ELF file: Invalid Version"),
        }

        match self.e_ident[7] {
            0 => println!("ELF file: OS ABI: No extensions or unspecified"),
            1 => println!("ELF file: OS ABI: Hewlett-Packard HP-UX"),
            2 => println!("ELF file: OS ABI: NetBSD"),
            3 => println!("ELF file: OS ABI: Linux"),
            6 => println!("ELF file: OS ABI: Sun Solaris"),
            7 => println!("ELF file: OS ABI: AIX"),
            8 => println!("ELF file: OS ABI: IRIX"),
            9 => println!("ELF file: OS ABI: FreeBSD"),
            10 => println!("ELF file: OS ABI: TRU64 UNIX"),
            11 => println!("ELF file: OS ABI: Novell Modesto"),
            12 => println!("ELF file: OS ABI: Open BSD"),
            13 => println!("ELF file: OS ABI: Open VMS"),
            14 => println!("ELF file: OS ABI: Hewlett-Packard Non-Stop Kernel"),
            97 => println!("ELF file: OS ABI: ARM architecture"),
            255 => println!("ELF file: OS ABI: Stand-alone (embedded)"),
            x if x >= 0x40 && x < 0xFF => println!("ELF file: OS ABI: Architecture-specific value range"),
            _ => panic!("Not an ELF file: Invalid OS ABI"),
        }

        match self.e_ident[8] {
            0 => println!("ELF file: ABI Version: None/Unspecified"),
            x => println!("ELF file: ABI Version: {}", x),
        }

        for i in 0..8 {
            if self.e_ident[i+8] != 0x00 {
                panic!("Not an ELF file: Invalid Padding");
            }
        }
    }




    fn validate_elf_type(&self) {
        match self.e_type {
            0 => println!("ELF file: Type: No file type"),
            1 => println!("ELF file: Type: Relocatable file"),
            2 => println!("ELF file: Type: Executable file"),
            3 => println!("ELF file: Type: Shared object file"),
            4 => println!("ELF file: Type: Core file"),
            x if x >= 0xfe00 && x <= 0xfeff => println!("ELF file: Type: Operating system-specific"),
            x if x >= 0xff00 && x <= 0xffff => println!("ELF file: Type: Processor-specific"),
            _ => println!("ELF file: Type: Unknown"),
        }
    }


    
    fn validate_elf_machine(&self) {
        match self.e_machine {
            0 => println!("ELF file: Machine: None"),
            1 => println!("ELF file: Machine: AT&T WE 32100"),
            2 => println!("ELF file: Machine: SPARC"),
            3 => println!("ELF file: Machine: Intel 80386"),
            4 => println!("ELF file: Machine: Motorola 68000"),
            5 => println!("ELF file: Machine: Motorola 88000"),
            7 => println!("ELF file: Machine: Intel 80860"),
            8 => println!("ELF file: Machine: MIPS I Architecture"),
            9 => println!("ELF file: Machine: IBM System/370 Processor"),
            10 => println!("ELF file: Machine: MIPS RS3000 Little-endian"),
            15 => println!("ELF file: Machine: Hewlett-Packard PA-RISC"),
            17 => println!("ELF file: Machine: Fujitsu VPP500"),
            18 => println!("ELF file: Machine: Enhanced instruction set SPARC"),
            19 => println!("ELF file: Machine: Intel 80960"),
            20 => println!("ELF file: Machine: PowerPC"),
            21 => println!("ELF file: Machine: 64-bit PowerPC"),
            22 => println!("ELF file: Machine: IBM System/390 Processor"),
            36 => println!("ELF file: Machine: NEC V800"),
            37 => println!("ELF file: Machine: Fujitsu FR20"),
            38 => println!("ELF file: Machine: TRW RH-32"),
            39 => println!("ELF file: Machine: Motorola RCE"),
            40 => println!("ELF file: Machine: Advanced RISC Machines ARM"),
            41 => println!("ELF file: Machine: Digital Alpha"),
            42 => println!("ELF file: Machine: Hitachi SH"),
            43 => println!("ELF file: Machine: SPARC Version 9"),
            44 => println!("ELF file: Machine: Siemens TriCore embedded processor"),
            45 => println!("ELF file: Machine: Argonaut RISC Core"),
            46 => println!("ELF file: Machine: Hitachi H8/300"),
            47 => println!("ELF file: Machine: Hitachi H8/300H"),
            48 => println!("ELF file: Machine: Hitachi H8S"),
            49 => println!("ELF file: Machine: Hitachi H8/500"),
            50 => println!("ELF file: Machine: Intel IA-64 processor architecture"),
            51 => println!("ELF file: Machine: Stanford MIPS-X"),
            52 => println!("ELF file: Machine: Motorola ColdFire"),
            53 => println!("ELF file: Machine: Motorola M68HC12"),
            54 => println!("ELF file: Machine: Fujitsu MMA Multimedia Accelerator"),
            55 => println!("ELF file: Machine: Siemens PCP"),
            56 => println!("ELF file: Machine: Sony nCPU embedded RISC processor"),
            57 => println!("ELF file: Machine: Denso NDR1 microprocessor"),
            58 => println!("ELF file: Machine: Motorola Star*Core processor"),
            59 => println!("ELF file: Machine: Toyota ME16 processor"),
            60 => println!("ELF file: Machine: STMicroelectronics ST100 processor"),
            61 => println!("ELF file: Machine: Advanced Logic Corp. TinyJ processor family"),
            62 => println!("ELF file: Machine: AMD x86-64 architecture"),
            63 => println!("ELF file: Machine: Sony DSP Processor"),
            64 => println!("ELF file: Machine: Digital Equipment Corp. PDP-10"),
            65 => println!("ELF file: Machine: Digital Equipment Corp. PDP-11"),
            66 => println!("ELF file: Machine: Siemens FX66 microcontroller"),
            67 => println!("ELF file: Machine: STMicroelectronics ST9+ 8/16 bit microcontroller"),
            68 => println!("ELF file: Machine: STMicroelectronics ST7 8-bit microcontroller"),
            69 => println!("ELF file: Machine: Motorola MC68HC16 Microcontroller"),
            70 => println!("ELF file: Machine: Motorola MC68HC11 Microcontroller"),
            71 => println!("ELF file: Machine: Motorola MC68HC08 Microcontroller"),
            72 => println!("ELF file: Machine: Motorola MC68HC05 Microcontroller"),
            73 => println!("ELF file: Machine: Silicon Graphics SVx"),
            74 => println!("ELF file: Machine: STMicroelectronics ST19 8-bit microcontroller"),
            75 => println!("ELF file: Machine: Digital VAX"),
            76 => println!("ELF file: Machine: Axis Communications 32-bit embedded processor"),
            77 => println!("ELF file: Machine: Infineon Technologies 32-bit embedded processor"),
            78 => println!("ELF file: Machine: Element 14 64-bit DSP Processor"),
            79 => println!("ELF file: Machine: LSI Logic 16-bit DSP Processor"),
            80 => println!("ELF file: Machine: Donald Knuth's educational 64-bit processor"),
            81 => println!("ELF file: Machine: Harvard University object files"),
            82 => println!("ELF file: Machine: SiTera Prism"),
            83 => println!("ELF file: Machine: Atmel AVR 8-bit microcontroller"),
            84 => println!("ELF file: Machine: Fujitsu FR30"),
            85 => println!("ELF file: Machine: Mitsubishi D10V"),
            86 => println!("ELF file: Machine: Mitsubishi D30V"),
            87 => println!("ELF file: Machine: NEC v850"),
            88 => println!("ELF file: Machine: Mitsubishi M32R"),
            89 => println!("ELF file: Machine: Matsushita MN10300"),
            90 => println!("ELF file: Machine: Matsushita MN10200"),
            91 => println!("ELF file: Machine: picoJava"),
            92 => println!("ELF file: Machine: OpenRISC 32-bit embedded processor"),
            93 => println!("ELF file: Machine: ARC Cores Tangent-A5"),
            94 => println!("ELF file: Machine: Tensilica Xtensa Architecture"),
            95 => println!("ELF file: Machine: Alphamosaic VideoCore processor"),
            96 => println!("ELF file: Machine: Thompson Multimedia General Purpose Processor"),
            97 => println!("ELF file: Machine: National Semiconductor 32000 series"),
            98 => println!("ELF file: Machine: Tenor Network TPC processor"),
            99 => println!("ELF file: Machine: Trebia SNP 1000 processor"),
            100 => println!("ELF file: Machine: STMicroelectronics ST200 microcontroller"),
            _ => panic!("Not an ELF file: Invalid Machine Type"),
        }
    }

    fn validate_elf_version(&self) {
        match self.e_version {
            0 => println!("ELF file: Version: None"),
            1 => println!("ELF file: Version: Current"),
            _ => panic!("Not an ELF file: Invalid Version"),
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
            e_type: 0,
            e_machine: 0,
            e_version: 0,
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

    pub fn read_bytes(&mut self,bytes: &[u8]) ->  Self {
        Self {
            e_ident: bytes[0..EI_NIDENT].try_into().unwrap(),
            e_type: u16::from_le_bytes(bytes[EI_NIDENT..EI_NIDENT+2].try_into().unwrap()),
            e_machine: u16::from_le_bytes(bytes[EI_NIDENT+2..EI_NIDENT+4].try_into().unwrap()),
            e_version: u32::from_le_bytes(bytes[EI_NIDENT+4..EI_NIDENT+8].try_into().unwrap()),
            e_entry: ElfNAddr::from_le_bytes(bytes[EI_NIDENT+8..EI_NIDENT+16].try_into().unwrap()), // 64 bit -  need to read in 8 bytes  
            e_phoff: ElfNOff::from_le_bytes(bytes[EI_NIDENT+16..EI_NIDENT+24].try_into().unwrap()), // 64 bit
            e_shoff: ElfNOff::from_le_bytes(bytes[EI_NIDENT+24..EI_NIDENT+32].try_into().unwrap()),
            e_flags: u32::from_le_bytes(bytes[EI_NIDENT+32..EI_NIDENT+36].try_into().unwrap()),
            e_ehsize: u16::from_le_bytes(bytes[EI_NIDENT+36..EI_NIDENT+38].try_into().unwrap()),
            e_phentsize: u16::from_le_bytes(bytes[EI_NIDENT+38..EI_NIDENT+40].try_into().unwrap()),
            e_phnum: u16::from_le_bytes(bytes[EI_NIDENT+40..EI_NIDENT+42].try_into().unwrap()),
            e_shentsize: u16::from_le_bytes(bytes[EI_NIDENT+42..EI_NIDENT+44].try_into().unwrap()),
            e_shnum: u16::from_le_bytes(bytes[EI_NIDENT+44..EI_NIDENT+46].try_into().unwrap()),
            e_shstrndx: u16::from_le_bytes(bytes[EI_NIDENT+46..EI_NIDENT+48].try_into().unwrap()),
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
        if self.e_ident[4] == 1 {
            let mut program_headers: Vec<Elf32_Phdr> = Vec::new();
            let mut offset = self.e_phoff as usize;
            for i in 0..self.e_phnum as usize {
                let phdr = Elf32_Phdr::read_bytes(file_bytes, offset);
                phdr.print(i);
                program_headers.push(phdr);
                offset += self.e_phentsize as usize;
            }
        } else if self.e_ident[4] == 2 {
            let mut program_headers: Vec<Elf64_Phdr> = Vec::new();
            let mut offset = self.e_phoff as usize;
            for i in 0..self.e_phnum as usize {
                let phdr = Elf64_Phdr::read_bytes(file_bytes, offset);
                phdr.print(i);
                program_headers.push(phdr);
                offset += self.e_phentsize as usize;
            }
        }


        // program seciton parsing 
        if self.e_ident[4] == 1 {
            let mut section_headers: Vec<Elf32_Shdr> = Vec::new();
            let mut offset = self.e_shoff as usize;
            for i in 0..self.e_shnum as usize {
                let shdr = Elf32_Shdr::read_bytes(file_bytes, offset);
                shdr.print(i, file_bytes);
                section_headers.push(shdr);
                offset += self.e_shentsize as usize;
            }
        } else if self.e_ident[4] == 2 {
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