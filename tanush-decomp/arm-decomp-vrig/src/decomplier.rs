
// arm decomplier 


impl Decomplier {
    pub fn decomplier_init(file_bytes: &[u8]) {
        self.file_bytes = file_bytes.to_vec();
    }


    pub fn decomplier_start(&self, vaddr: u64, memsz: u64, filesz: u64) {
        let start_addr = vaddr;
        let end_addr = vaddr + memsz;
        let file_data = &self.file_bytes[start_addr..end_addr];
        println!("Decomplier load section: 0x{:016X} - 0x{:016X}", start_addr, end_addr);
        println!("File data: {:?}", file_data);
        let dissambled_code = self.dissamble_section(vaddr, memsz, filesz);

    }

    pub fn dissamble_section(&self, vaddr: u64, memsz: u64, filesz: u64) {
        let start_addr = vaddr;
        let end_addr = vaddr + memsz;
        let file_data = &self.file_bytes[start_addr..end_addr];
        println!("Decomplier load section: 0x{:016X} - 0x{:016X}", start_addr, end_addr);
        println!("File data: {:?}", file_data);

        for i in 0..file_data.len() {




    }
}

