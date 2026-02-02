
// arm decomplier 





#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcodes {
    ADC, ADD, AND, B,
    BIC, BL, BX, CDP,
    CMN, CMP, EOR, LDC,
    LDM, LDR, MCR, MLA,
    MOV, MRC, MRS, MSR,
    MUL, MVN, ORR, RSB,
    RSC, SBC, STC, STM,
    STR, SUB, SWI, SWP,
    TEQ, TST,
}

pub enum ShiftType {
    LSL,
    LSR,
    ASR,
    ROR,
}


pub impl ShiftType {
    pub fn from_str(s: &str) -> Self {
        match s {
            "LSL" => ShiftType::LSL,
            "LSR" => ShiftType::LSR,
            "ASR" => ShiftType::ASR,
            "ROR" => ShiftType::ROR,
        }
    }


    

pub struct Instruction {
    condition: String,
    opcode: Opcodes,
    operands: Vec<String>,
}


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


    fn parse_condition(&self, condition_bits: Vec<String>) -> String {
        // 0000 EQ Z set equal
        // 0001 NE Z clear not equal
        // 0010 CS C set unsigned higher or same
        // 0011 CC C clear unsigned lower
        // 0100 MI N set negative
        // 0101 PL N clear positive or zero
        // 0110 VS V set overflow
        // 0111 VC V clear no overflow
        // 1000 HI C set and Z clear unsigned higher
        // 1001 LS C clear or Z set unsigned lower or same
        // 1010 GE N equals V greater or equal
        // 1011 LT N not equal to V less than
        // 1100 GT Z clear AND (N equals V) greater than
        // 1101 LE Z set OR (N not equal to V) less than or equal
        // 1110 AL (ignored) always
        let condition = match condition_bits {
            "0000" => "EQ",
            "0001" => "NE",
            "0010" => "CS",
            "0011" => "CC",
            "0100" => "MI",
            "0101" => "PL",
            "0110" => "VS",
            "0111" => "VC",
            "1000" => "HI",
            "1001" => "LS",
            "1010" => "GE",
            "1011" => "LT",
            "1100" => "GT",
            "1101" => "LE",
            "1110" => "AL",
            _ => "AL",
        return condition;
    }


    fn data_processing_opcode_parse(bits: Vec<String>) -> Opcodes {
        let opcode = match bits {
            "0000" => Opcodes::AND,
            "0001" => Opcodes::EOR,
            "0010" => Opcodes::SUB,
            "0011" => Opcodes::RSB,
            "0100" => Opcodes::ADD,
            "0101" => Opcodes::ADC,
            "0110" => Opcodes::SBC,
            "0111" => Opcodes::RSC,
            "1000" => Opcodes::TST,
            "1001" => Opcodes::TEQ,
            "1010" => Opcodes::CMP,
            "1011" => Opcodes::CMN,
            "1100" => Opcodes::ORR,
            "1101" => Opcodes::MOV,
            "1110" => Opcodes::BIC,
            "1111" => Opcodes::MVN,
        }
        return opcode;
    }

    fn parse_instruction(&self,bits: Vec<String>) -> Instruction {

        let condition_bits = bits[0..4].to_vec();
        let condition = self.parse_condition(condition_bits);


        // BX
        // 0001-0010-1111-1111-1111-0001
        // Parse the bit pattern starting at bits[3] exactly in the given order:
        // bits[3]=0, bits[4]=0, bits[5]=0, bits[6]=1, bits[7]=0, bits[8]=0, bits[9]=1, bits[10]=0, bits[11]=1, bits[12]=1, bits[13]=1, bits[14]=1, bits[15]=1, bits[16]=1, bits[17]=1, bits[18]=1, bits[19]=1, bits[20]=1, bits[21]=0, bits[22]=0, bits[23]=0, bits[24]=1
        if bits[3] == "0"
            && bits[4] == "0"
            && bits[5] == "0"
            && bits[6] == "1"
            && bits[7] == "0"
            && bits[8] == "0"
            && bits[9] == "1"
            && bits[10] == "0"
            && bits[11] == "1"
            && bits[12] == "1"
            && bits[13] == "1"
            && bits[14] == "1"
            && bits[15] == "1"
            && bits[16] == "1"
            && bits[17] == "1"
            && bits[18] == "1"
            && bits[19] == "1"
            && bits[20] == "1"
            && bits[21] == "0"
            && bits[22] == "0"
            && bits[23] == "0"
            && bits[24] == "1"
        {
            let target_register = bits[27..32].to_vec().join("").parse::<i32>().unwrap();
            let target_register = format!("R{}", target_register);
            return Instruction { condition, opcode: Opcodes::BX, operands: vec![target_register] };
        }


        // Branch ins works by 
        if (bits[3] == "1"
            && bits[4] == "0"
            && bits[5] == "1"
        ){
            // link bit ? 
            // this will write the old PC into the link registe of the current bank 
            let offsetval = bits[7..32].to_vec().join("").parse::<i32>().unwrap();
            let offset = offset << 2;
            let offset = offsetval + vaddr;
            if (bits[6] == "1") {
                return Instruction { condition, opcode: Opcodes::BL, operands: vec![offset] };
            } else {
                return Instruction { condition, opcode: Opcodes::B, operands: vec![offset] };
            }

        }


        // Data processing instructions
        if (bits[3] == "0"
            && bits[4] == "0"
        ) {
            if (bits[5] == "0") {
                // parse 2nd bit as am immmedate value 
                let opcode = self.data_processing_opcode_parse(bits[6..10].to_vec());
                let condition_codes = bits[11];
                //  0 = do not alter condition codes
                //  1 = set condition codes
                 
                reg1 = bits[12..16].to_vec().join("").parse::<i32>().unwrap();
                reg1 = format!("R{}", reg1);
                reg2 = bits[16..20].to_vec().join("").parse::<i32>().unwrap();
                reg2 = format!("R{}", reg2);

                // 4 bits
                let rotate_amount = bits[20..24].to_vec().join("").parse::<i32>().unwrap();
                let immmedate = bits[24..31].to_vec().join("").parse::<i32>().unwrap();

                let immmedate = immmedate << rotate_amount;
                return Instruction { condition, opcode, operands: vec![reg1, reg2, immmedate.to_string(), condition_codes.to_string()] };






            else {
                let opcode = self.data_processing_opcode_parse(bits[6..10].to_vec());
                let condition_codes = bits[11].clone();
                let reg1 = bits[12..16].to_vec().join("").parse::<i32>().unwrap();
                let reg1 = format!("R{}", reg1);
                let reg2 = bits[16..20].to_vec().join("").parse::<i32>().unwrap();
                let reg2 = format!("R{}", reg2);
                let shift_amount = bits[20..25].to_vec().join("").parse::<i32>().unwrap();
                let shift_type = bits[25..27].to_vec().join("");
                let stype_str = match shift_type.as_str() {
                    "00" => "LSL",
                    "01" => "LSR",
                    "10" => "ASR",
                    "11" => "ROR",
                    _ => "LSL",
                };
                let rm = bits[28..32].to_vec().join("").parse::<i32>().unwrap();
                let reg3 = if shift_amount == 0 && stype_str == "ROR" {
                    format!("R{}, RRX", rm)
                } else {
                    format!("R{}, {} #{}", rm, stype_str, shift_amount)
                };
                return Instruction { condition, opcode, operands: vec![reg1, reg2, reg3, condition_codes.to_string()] };
            }


        // let opcode_bits = bits[4..8].to_vec();
        // let opcode = self.parse_opcode(opcode_bits);

        // let operands_bits = bits[8..12].to_vec();
        // let operands = self.parse_operands(operands_bits);

        return Instruction { condition, opcode, operands };
    }

    pub fn dissamble_section(&self, vaddr: u64, memsz: u64, filesz: u64) {
        let start_addr = vaddr;
        let end_addr = vaddr + memsz;
        let file_data = &self.file_bytes[start_addr..end_addr];
        println!("Decomplier load section: 0x{:016X} - 0x{:016X}", start_addr, end_addr);
        println!("File data: {:?}", file_data);
        //ff,43,00,d1
        for i in (0..file_data.len()).step_by(4) {
            let word = file_data[i..i+4].to_vec();
            let bits = word.iter().map(|b| b.to_string()).collect::<Vec<String>>();

            let instruction = self.parse_instruction(bits);
            println!("Instruction: {:?}", instruction);









        }




    }
}

