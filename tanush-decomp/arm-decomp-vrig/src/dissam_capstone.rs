use crate::decomplier::Decomplier;
use capstone::{
    Capstone,
    arch::{arm, arm64},
    prelude::*,
};

pub struct DecomplierCapstone {
    capstone: Capstone,
}

impl DecomplierCapstone {
    pub fn new_arm32() -> Self {
        let cs = Capstone::new()
            .arm()
            .mode(arm::ArchMode::Arm)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");
        DecomplierCapstone { capstone: cs }
    }

    pub fn new_arm64() -> Self {
        let cs = Capstone::new()
            .arm64()
            .mode(arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");
        DecomplierCapstone { capstone: cs }
    }

    pub fn dissamble_section32bit(
        &self,
        file_bytes: &[u8],
        file_offset: u64,
        vaddr: u64,
        _memsz: u32,
        filesz: u32,
    ) {
        self.disassemble(file_bytes, file_offset, vaddr, filesz as u64);
    }

    pub fn dissamble_section64bit(
        &self,
        file_bytes: &[u8],
        file_offset: u64,
        vaddr: u64,
        _memsz: u64,
        filesz: u64,
    ) {
        self.disassemble(file_bytes, file_offset, vaddr, filesz);
    }

    fn disassemble(&self, file_bytes: &[u8], file_offset: u64, vaddr: u64, filesz: u64) {
        if filesz == 0 {
            return;
        }

        let start = file_offset as usize;
        if start >= file_bytes.len() {
            eprintln!("Section offset 0x{file_offset:016X} is outside the file bounds");
            return;
        }

        let max_len = file_bytes.len();
        let mut end = start.saturating_add(filesz as usize);
        if end > max_len {
            eprintln!(
                "Section at offset 0x{file_offset:016X} truncated: requested {filesz} bytes, clamping to file size"
            );
            end = max_len;
        }

        if end <= start {
            eprintln!(
                "Section at offset 0x{file_offset:016X} has invalid size {filesz} (end before start)"
            );
            return;
        }

        let data = &file_bytes[start..end];
        match self.capstone.disasm_all(data, vaddr) {
            Ok(insns) => {
                for insn in insns.iter() {
                    // println!("--------------------------------");
                    println!("{insn}");
                    if let Ok(detail) = self.capstone.insn_detail(&insn) {
                        let arch_detail = detail.arch_detail();
                        for op in arch_detail.operands() {
                            // println!("    {:?}", op);
                        }
                    }
                }

                let mut decomplier = Decomplier::new(insns);
                decomplier.start_decomplier();
            }

            Err(err) => {
                eprintln!("Failed to disassemble section at 0x{vaddr:016X} (size {filesz}): {err}");
            }
        }
    }
}
