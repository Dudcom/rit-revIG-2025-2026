mod decomplier;
mod dissam_capstone;
mod elf_dynamic;
mod elf_header;
mod elf_notes;
mod elf_programheaders;
mod elf_relocation;
mod elf_sectionheaders;
mod elf_symbol;
use elf_header::ElfNEhdr;
use std::env;
use std::fs::File;
use std::io::Read;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <binary file>", args[0]);
        return;
    }

    let binary_file = &args[1];

    let mut file = File::open(binary_file).expect("Failed to open file");

    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes)
        .expect("Failed to read file");

    let mut header_buffer = [0; 0x40];
    header_buffer.copy_from_slice(&file_bytes[0..0x40]);
    println!("Header buffer: {:?}", &header_buffer[0..4]);
    let mut header = ElfNEhdr::new();
    header.read_bytes(&header_buffer).validate(&file_bytes);
}
