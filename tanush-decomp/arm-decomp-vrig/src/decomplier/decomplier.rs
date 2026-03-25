use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::rc::Rc;

use capstone::{Insn, Instructions};

#[derive(Debug)]
struct BasicBlockNode<'insn> {
    id: usize,
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
            id: 0,
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

#[derive(Debug)]
struct CFG {
    successors: HashMap<usize, HashSet<usize>>,
    predecessors: HashMap<usize, HashSet<usize>>,
}

pub struct Decomplier<'insn> {
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

        // if we are revisiting the same block
        // we need this in order to detect loops
        if let Some(existing) = cache.get(&start_idx) {
            return Rc::clone(existing);
        }

        let node = BasicBlockNode::new_ref();
        node.borrow_mut().id = start_idx;
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
                    //println!("Target index: {:#?}", target_idx);
                    let left_block = Self::basic_blocks_analysis(instructions, address_to_index, target_idx, cache);

                    // we check if the ins is a "fallthrough" ins
                    if !Self::has_fallthrough(&mnemonic) {
                        end_addr = instructions
                            .get(target_idx)
                            .map(|target_insn: &Insn<'insn>| target_insn.address());

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

    fn build_successor_predecessor(
        // we find successor and pred for each block 
        cache: &HashMap<usize, Rc<RefCell<BasicBlockNode<'insn>>>>,
    )-> CFG{
        let mut succ = HashMap::<usize, HashSet<usize>>::new();
        let mut pred = HashMap::<usize, HashSet<usize>>::new();
        for node in cache.values(){
            let borrowed_node = node.borrow();
            let id = borrowed_node.id;

            succ.entry(id).or_default();
            pred.entry(id).or_default();

            if let Some(left) = &borrowed_node.left {
                let succ_id = left.borrow().id;
                succ.entry(id).or_default().insert(succ_id);
                pred.entry(succ_id).or_default().insert(id);
            }
            if let Some(right) = &borrowed_node.right {
                let succ_id = right.borrow().id;
                succ.entry(id).or_default().insert(succ_id);
                pred.entry(succ_id).or_default().insert(id);
            }
        }
        CFG {
            successors: succ,
            predecessors: pred,
        }
    }

    fn natural_loop_block_ids(cfg: &CFG, header: usize, tail: usize) -> Vec<usize> {
        // we have walk to the cfg till header == tail, while header!=tail
        // we add the block to `blocks`
        let mut blocks = HashSet::new();
        blocks.insert(header);
        if header != tail {
            blocks.insert(tail);
            let mut worklist = vec![tail];
            while let Some(b) = worklist.pop() {
                let Some(preds) = cfg.predecessors.get(&b) else {
                    continue;
                };
                for &p in preds {
                    if !blocks.contains(&p) {
                        blocks.insert(p);
                        worklist.push(p);
                    }
                }
            }
        }
        let mut ids: Vec<usize> = blocks.into_iter().collect();
        ids.sort_unstable();
        ids
    }

    fn print_block_instructions(
        instructions: &Instructions<'insn>,
        cache: &HashMap<usize, Rc<RefCell<BasicBlockNode<'insn>>>>,
        block_id: usize,
    ) {
        let Some(node_rc) = cache.get(&block_id) else {
            println!("  block {block_id}: <missing>");
            return;
        };
        let borrowed = node_rc.borrow();
        for &ins_idx in &borrowed.instruction {
            if let Some(insn) = instructions.get(ins_idx) {
                let addr = insn.address();
                let mnemonic = insn.mnemonic().unwrap_or("<unknown>");
                let operands = insn.op_str().unwrap_or("");
                if operands.is_empty() {
                    println!("  {addr:#010x}: {mnemonic}");
                } else {
                    println!("  {addr:#010x}: {mnemonic} {operands}");
                }
            }
        }
    }

    fn dump_natural_loop_edge(
        instructions: &Instructions<'insn>,
        cache: &HashMap<usize, Rc<RefCell<BasicBlockNode<'insn>>>>,
        cfg: &CFG,
        header: usize,
        tail: usize,
    ) {
        let loop_blocks = Self::natural_loop_block_ids(cfg, header, tail);
        println!("Natural loop (back edge {tail} -> {header})");
        println!("--------------------------------");
        println!("blocks: {loop_blocks:?}");
        for block_id in &loop_blocks {
            println!("block {block_id}:");
            Self::print_block_instructions(instructions, cache, *block_id);
        }
        println!("--------------------------------");
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
        // self.print_basic_blocks();


        // println!("cache: {:#?}", cache);





        let mut dom: HashMap<usize, HashSet<usize>> = HashMap::new();
        let cfg = Self::build_successor_predecessor(&cache);
        // println!("CFG: {:#?}", cfg);
        let all_nodes: HashSet<_> = cfg.successors.keys().copied().collect();

        const ENTRY: usize = 0;
        if all_nodes.is_empty() {
            return;
        }

        for &node in &all_nodes {
            if node == ENTRY {
                dom.insert(node, HashSet::from([ENTRY]));
            } else {
                dom.insert(node, all_nodes.clone());
            }
        }

        let mut node_order: Vec<usize> = all_nodes.iter().copied().collect();
        node_order.sort_unstable();

        loop {
            let mut changed = false;

            for &node in &node_order {
                if node == ENTRY {
                    continue;
                }

                let preds = match cfg.predecessors.get(&node) {
                    Some(p) => p,
                    None => continue,
                };
                if preds.is_empty() {
                    continue;
                }

                let mut new_dom = all_nodes.clone();
                for p in preds {
                    let pred_dom = dom
                        .get(p)
                        .expect("predecessor block should have a dominator set");
                    new_dom = new_dom
                        .intersection(pred_dom)
                        .copied()
                        .collect();
                }

                new_dom.insert(node);

                if dom.get(&node) != Some(&new_dom) {
                    dom.insert(node, new_dom);
                    changed = true;
                }
            }

            if !changed {
                break;
            }
        }

        println!("Dominator tree: {:#?}", dom);
        println!("--------------------------------");

        let mut seen_back_edges = HashSet::new();

        for &block in &node_order {
            if block == ENTRY {
                continue;
            }
            let Some(succs) = cfg.successors.get(&block) else {
                continue;
            };
            for &succ in succs {
                if dom
                    .get(&block)
                    .is_some_and(|d| d.contains(&succ))
                    && seen_back_edges.insert((succ, block))
                {
                    println!("back edge: tail {block} -> header {succ}");
                    Self::dump_natural_loop_edge(
                        &instructions,
                        &cache,
                        &cfg,
                        succ,
                        block,
                    );
                }
            }
        }
    }
}
