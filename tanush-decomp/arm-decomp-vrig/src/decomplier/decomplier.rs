use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::rc::Rc;

use capstone::{Insn, Instructions};

#[derive(Debug)]
struct BasicBlockNode<'insn> {
    instruction: Vec<usize>,
    start_addr: Option<u64>,
    end_addr: Option<u64>,
    left: Option<Rc<RefCell<BasicBlockNode<'insn>>>>, // we use ref count ptr since multiple blocks can point to the same node
    right: Option<Rc<RefCell<BasicBlockNode<'insn>>>>, // tldr is we keep track of objs that point to this pointer, it inc the internal ref cound and only frees the obj when the ref count is 0
    _marker: PhantomData<&'insn ()>, // some rust life time fix that I lowkey don't care to understand
}

impl<'insn> BasicBlockNode<'insn> {
    fn new() -> Self {
        Self {
            instruction: Vec::new(),
            start_addr: None,
            end_addr: None,
            left: None,
            right: None,
            _marker: PhantomData,
        }
    }

    fn new_ref() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self::new()))
    }
}

/// Skeleton container for the upcoming high level decompiler.
pub struct Decomplier<'insn> {
    // basic_blocks: Vec<Instructions<'insn>>,
    instructions: Rc<Instructions<'insn>>,
    address_to_index: Rc<HashMap<u64, usize>>,
    roots: Vec<Rc<RefCell<BasicBlockNode<'insn>>>>,
}

impl<'insn> Decomplier<'insn> {
    /// Initializes the analysis state by keeping the full instruction list accessible for later lookups.
    pub fn new(all_instructions: Instructions<'insn>) -> Self {
        let instructions = Rc::new(all_instructions);

        // create a hashmap to map the address to the index of the instruction
        let address_to_index = Rc::new(
            instructions
                .iter()
                .enumerate()
                .map(|(idx, insn)| (insn.address(), idx))
                .collect(),
        );

        //println!("Address to index: {:#?}", address_to_index);
        // 0x75c: nop
        // 0x760: stp x29, x30, [sp, #-0x10]!
        // 0x764: mov x29, sp
        // 0x768: ldp x29, x30, [sp], #0x10
        // 0x76c: ret
        // Address to index: {
        //     1900: 4,
        //     1892: 2,
        //     1884: 0,
        //     1888: 1,
        //     1896: 3,
        // }

        Self {
            instructions,
            address_to_index,
            roots: Vec::new(),
        }
    }

    fn is_jump(ins: &Insn<'insn>) -> bool {
        let Some(mnemonic) = ins.mnemonic() else {
            return false;
        };

        // we are finding all possible changes in the control flow
        let normalized = mnemonic.to_ascii_lowercase();
        matches!(normalized.as_str(), "b" | "bl" | "blr" | "br" | "ret")
            || matches!(normalized.as_str(), "cbz" | "cbnz" | "tbz" | "tbnz")
            || normalized.starts_with("b.") // we love rust
    }

    fn basic_blocks_analysis(
        instructions: &Instructions<'insn>,
        address_to_index: &HashMap<u64, usize>,
        start_idx: usize,
        cache: &mut HashMap<usize, Rc<RefCell<BasicBlockNode<'insn>>>>,
    ) -> Rc<RefCell<BasicBlockNode<'insn>>> {
        // our base case is when we are out of instructions
        if start_idx >= instructions.len() {
            return BasicBlockNode::new_ref();
        }

        // if we are revisiting the same block, return the cached block
        // memoization bs 
        if let Some(existing) = cache.get(&start_idx) {
            return Rc::clone(existing);
        }

        let node = BasicBlockNode::new_ref();
        cache.insert(start_idx, Rc::clone(&node));

        let mut i = start_idx;
        let mut blk_ins = Vec::new(); // the ins in our block 
        let mut start_addr = None;
        let mut end_addr = None;

        // we go through all instructions and use recursion to build leafs
        while let Some(insn) = instructions.get(i) {
            blk_ins.push(i);
            start_addr.get_or_insert_with(|| insn.address());

            // we need to start creating branches when we have changes in control flow
            if Self::is_jump(insn) {
                let mnemonic = insn
                    .mnemonic()
                    .map(|m| m.to_ascii_lowercase())
                    .unwrap_or_default();

                if let Some(target_idx) = Self::jump_target_index(address_to_index, insn) {
                    println!("Target index: {:#?}", target_idx);
                    let left_block = Self::basic_blocks_analysis(instructions, address_to_index, target_idx, cache);

                    // we check if the ins is a "fallthrough" ins
                    if !Self::has_fallthrough(&mnemonic) {
                        end_addr = instructions
                            .get(target_idx)
                            .map(|target_insn| target_insn.address()); // get the addr of the instruction if it is a fallthrough

                        // if the end addr fails 
                        if end_addr.is_none() {
                            end_addr = insn
                                .op_str()
                                .and_then(Self::get_addr_helper);
                        }
                    }
                    node.borrow_mut().left = Some(left_block);
                } else if !Self::has_fallthrough(&mnemonic) {
                    end_addr = insn.op_str().and_then(Self::get_addr_helper);
                }

                if Self::has_fallthrough(&mnemonic) && i + 1 < instructions.len() {
                    // the right block now becomes the instrcutiosn after the follow through
                    let right_block = Self::basic_blocks_analysis(instructions, address_to_index, i + 1, cache);


                    node.borrow_mut().right = Some(right_block);
                    end_addr = instructions
                        .get(i + 1)
                        .map(|next_insn| next_insn.address());
                }
                break;
            }
            
            // always inc the idx
            i += 1;
        }

        // the case where our end block is the final instruction
        // ie no b / br / ret
        if end_addr.is_none() {
            let next_idx = i + 1;
            if next_idx < instructions.len() {
                if let Some(next_insn) = instructions.get(next_idx) {
                    end_addr = Some(next_insn.address());
                }
            }
        }

        {
            let mut borrowed = node.borrow_mut();
            borrowed.instruction = blk_ins;
            borrowed.start_addr = start_addr;
            borrowed.end_addr = end_addr;
        }
        node
    }

    fn update_coverage(
        cache: &HashMap<usize, Rc<RefCell<BasicBlockNode<'insn>>>>,
        seen_blocks: &mut HashSet<usize>,
        seen_ins: &mut HashSet<usize>,
    ) {
        for (&idx, node) in cache.iter() {
            if !seen_blocks.insert(idx) {
                continue;
            }
            let borrowed = node.borrow();
            for &ins_idx in &borrowed.instruction {
                seen_ins.insert(ins_idx);
            }
        }
    }

    fn jump_target_index(
        address_to_index: &HashMap<u64, usize>,
        insn: &Insn<'insn>,
    ) -> Option<usize> {
        // return the index in the hashmap
        let op_str = insn.op_str()?;
        let address = Self::get_addr_helper(op_str)?;
        // println!("Address: {:#010x} -> Index: {:#?}", address, address_to_index.get(&address).copied());
        address_to_index.get(&address).copied() 
    }

    // simple helper func to get addr from capstone 
    fn get_addr_helper(operand: &str) -> Option<u64> {
        let target = operand.split(',').last()?.trim();
        let cleaned = target.trim_start_matches(|ch| ch == '#' || ch == '=' || ch == ' ');

        if let Some(hex) = cleaned
            .strip_prefix("0x")
            .or_else(|| cleaned.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16).ok()
        } else {
            cleaned.parse().ok()
        }
    }


    // we have to stop spliting the block on these instructions
    fn has_fallthrough(mnemonic: &str) -> bool {
        !matches!(mnemonic, "b" | "br" | "ret")
    }


    // ngl this was AI lol 
    fn print_basic_blocks(&self) {
        println!("Basic Blocks");
        println!("============");
        for (idx, node) in self.roots.iter().enumerate() {
            if idx > 0 {
                println!();
            }
            let mut visited = HashSet::new();
            let label = if idx == 0 {
                "entry".to_string()
            } else {
                let start_addr = node.borrow().start_addr;
                start_addr
                    .map(|addr| format!("entry@{addr:#010x}"))
                    .unwrap_or_else(|| format!("entry#{idx}"))
            };
            self.print_block(node, 0, &label, &mut visited);
        }
    }

    // ngl this was AI lol 
    fn print_block(
        &self,
        node: &Rc<RefCell<BasicBlockNode<'insn>>>,
        depth: usize,
        label: &str,
        visited: &mut HashSet<usize>,
    ) {
        let indent = "  ".repeat(depth);
        let node_id = Rc::as_ptr(node) as usize;
        if !visited.insert(node_id) {
            println!("{indent}- {label}: <revisited>");
            return;
        }

        let (instructions, start_addr, end_addr, left, right) = {
            let borrowed = node.borrow();
            (
                borrowed.instruction.clone(),
                borrowed.start_addr,
                borrowed.end_addr,
                borrowed.left.clone(),
                borrowed.right.clone(),
            )
        };

        if instructions.is_empty() && left.is_none() && right.is_none() {
            println!("{indent}- {label}: <empty>");
            return;
        }

        let count = instructions.len();
        let start_display = start_addr
            .map(|addr| format!("{addr:#010x}"))
            .unwrap_or_else(|| "<unknown>".to_string());
        let end_display = end_addr
            .map(|addr| format!("{addr:#010x}"))
            .unwrap_or_else(|| "<return>".to_string());
        println!(
            "{indent}- {label} [start={start_display}, end={end_display}] ({} instruction{})",
            count,
            if count == 1 { "" } else { "s" }
        );

        for idx in instructions {
            if let Some(insn) = self.instructions.get(idx) {
                let addr = insn.address();
                let mnemonic = insn.mnemonic().unwrap_or("<unknown>");
                let operands = insn.op_str().unwrap_or("");
                if operands.is_empty() {
                    println!("{indent}    {addr:#010x}: {mnemonic}");
                } else {
                    println!("{indent}    {addr:#010x}: {mnemonic} {operands}");
                }
            }
        }

        if let Some(left_node) = left {
            self.print_block(&left_node, depth + 1, "branch target", visited);
        }
        if let Some(right_node) = right {
            self.print_block(&right_node, depth + 1, "fallthrough", visited);
        }
    }

    pub fn start_decomplier(&mut self) {
        let instructions = Rc::clone(&self.instructions);
        let address_to_index = Rc::clone(&self.address_to_index);
        let mut cache = HashMap::new(); // global cache for memoization
        self.roots.clear();
        let mut seen_blocks = HashSet::new(); // set of blocks we have already seen
        let mut seen_ins = HashSet::new(); // set of instructions we have already covered

        // build root block
        if !instructions.is_empty() {
            let entry_block =
                Self::basic_blocks_analysis(&instructions, &address_to_index, 0, &mut cache);
            self.roots.push(entry_block);
            Self::update_coverage(&cache, &mut seen_blocks, &mut seen_ins);
        }

        // build all other blocks
        for idx in 0..instructions.len() {
            // if we have already covered this instruction, skip it
            if seen_ins.contains(&idx) {
                continue;
            }
            let block =
                Self::basic_blocks_analysis(&instructions, &address_to_index, idx, &mut cache);
            // updae the seen blocks and instructions
            Self::update_coverage(&cache, &mut seen_blocks, &mut seen_ins);
            self.roots.push(block);
        }
        self.print_basic_blocks();
    }
}
