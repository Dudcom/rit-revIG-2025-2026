use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::rc::Rc;

use capstone::{Insn, Instructions};



struct BasicBlockNode<'insn> {
    instruction: Vec<usize>,
    left: Option<Box<BasicBlockNode<'insn>>>,
    right: Option<Box<BasicBlockNode<'insn>>>,
    _marker: PhantomData<&'insn ()>,
}

impl<'insn> BasicBlockNode<'insn> {
    fn new() -> Self {
        Self {
            instruction: Vec::new(),
            left: None,
            right: None,
            _marker: PhantomData,
        }
    }
}


/// Skeleton container for the upcoming high level decompiler.
pub struct Decomplier<'insn> {
    // basic_blocks: Vec<Instructions<'insn>>,

    instructions: Rc<Instructions<'insn>>,
    address_to_index: Rc<HashMap<u64, usize>>,
    root: BasicBlockNode<'insn>,
}




impl<'insn> Decomplier<'insn> {
    /// Initializes the analysis state by keeping the full instruction list accessible for later lookups.
    pub fn new(all_instructions: Instructions<'insn>) -> Self {
        let instructions = Rc::new(all_instructions);
        let address_to_index = Rc::new(
            instructions
                .iter()
                .enumerate()
                .map(|(idx, insn)| (insn.address(), idx))
                .collect(),
        );

        Self {
            instructions,
            address_to_index,
            root: BasicBlockNode::new(),
        }
    }


    fn is_jump(ins: &Insn<'insn>) -> bool {
        const JUMP_MNEMONICS: [&str; 16] = [
            "b", "bl", "blx", "bx", "cbz", "cbnz", "tbz", "tbnz", "beq", "bne", "bpl", "bmi",
            "bhi", "bls", "bge", "blt",
        ];

        if let Some(mnemonic) = ins.mnemonic() {
            JUMP_MNEMONICS.iter().any(|candidate| candidate.eq_ignore_ascii_case(mnemonic))
        } else {
            false
        }
    }

    fn basic_blocks_analysis(
        instructions: &Instructions<'insn>,
        address_to_index: &HashMap<u64, usize>,
        node: &mut BasicBlockNode<'insn>,
        start_idx: usize,
        visited: &mut HashSet<usize>,
    ) {
        // here our goal is going to be using a 
        // recursive approach to building the cfg
        // every time we hit a jmp/change in the flow of control
        // the right becomse the instruciton after the jump
        // and the left becomes the instruction if we dont have a jump


        if start_idx >= instructions.len() || visited.contains(&start_idx) {
            return;
        }
        visited.insert(start_idx);

        let mut cursor = start_idx;
        while let Some(insn) = instructions.get(cursor) {
            if Self::is_jump(insn) {
                node.instruction.push(cursor);

                if let Some(target_idx) = Self::jump_target_index(address_to_index, insn) {
                    let mut left_block = BasicBlockNode::new();
                    Self::basic_blocks_analysis(
                        instructions,
                        address_to_index,
                        &mut left_block,
                        target_idx,
                        visited,
                    );
                    node.left = Some(Box::new(left_block));
                }

                if cursor + 1 < instructions.len() {
                    let mut right_block = BasicBlockNode::new();
                    Self::basic_blocks_analysis(
                        instructions,
                        address_to_index,
                        &mut right_block,
                        cursor + 1,
                        visited,
                    );
                    node.right = Some(Box::new(right_block));
                }
                break;
            } else {
                node.instruction.push(cursor); // add ins to current node
                // this is unqiue from the list of all instructions
                cursor += 1;
            }
        }
    }

    fn jump_target_index(
        address_to_index: &HashMap<u64, usize>,
        insn: &Insn<'insn>,
    ) -> Option<usize> {
        let op_str = insn.op_str()?;
        let address = Self::parse_target_address(op_str)?;
        address_to_index.get(&address).copied()
    }

    fn parse_target_address(operand: &str) -> Option<u64> {
        let target = operand.split(',').next()?.trim();
        let cleaned = target.trim_start_matches(|ch| ch == '#' || ch == '=' || ch == ' ');

        if let Some(hex) = cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else {
            cleaned.parse().ok()
        }
    }

    pub fn start_decomplier(&mut self) {
        let mut visited = HashSet::new();
        let instructions = Rc::clone(&self.instructions);
        let address_to_index = Rc::clone(&self.address_to_index);
        Self::basic_blocks_analysis(
            &instructions,
            &address_to_index,
            &mut self.root,
            0,
            &mut visited,
        );
    }
}
