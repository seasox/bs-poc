use iced_x86::{
    code_asm::*, BlockEncoderOptions, Decoder, DecoderOptions, Formatter, Instruction,
    NasmFormatter,
};
use memmap2::{Mmap, MmapMut};

use std::{collections::HashMap, error::Error, io::Write, mem, ops::DerefMut};

pub enum FlushingStrategy {
    LatestPossible,
    EarliestPossible,
}

pub enum FencingStrategy {
    LatestPossible,
    EarliestPossible,
}

pub trait Jitter {
    fn jit(
        num_acts_per_trefi: u64,
        flushing: FlushingStrategy,
        fencing: FencingStrategy,
        aggressor_pairs: &[u64],
        sync_each_ref: bool,
        num_aggressors_for_sync: usize,
        total_num_activations: i64,
    ) -> Result<Program, Box<dyn Error>>;
    fn call(&self) -> u32;
}

pub struct Program {
    code: Mmap,
    start: u64,
}

impl Jitter for Program {
    fn jit(
        num_acts_per_trefi: u64,
        flushing: FlushingStrategy,
        fencing: FencingStrategy,
        aggressor_pairs: &[u64],
        sync_each_ref: bool,
        num_aggressors_for_sync: usize,
        total_num_activations: i64,
    ) -> Result<Program, Box<dyn Error>> {
        let mut a = CodeAssembler::new(64)?;

        let mut start = a.create_label();
        let mut while1_begin = a.create_label();
        let mut while1_end = a.create_label();
        let mut for_begin = a.create_label();
        let mut for_end = a.create_label();

        a.set_label(&mut start)?;

        let num_timed_accesses: usize = num_aggressors_for_sync;

        // part 1: synchronize with the beginning of an interval
        // warmup
        for idx in 0..num_timed_accesses {
            a.mov(rax, aggressor_pairs[idx])?;
            a.mov(rbx, ptr(rax))?;
        }

        a.set_label(&mut while1_begin)?;

        for idx in 0..num_timed_accesses {
            a.mov(rax, aggressor_pairs[idx])?;
            a.clflushopt(ptr(rax))?;
        }

        // fence memory activations, retrieve timestamp
        a.mfence()?;
        a.rdtscp()?;
        a.lfence()?;
        a.mov(ebx, eax)?;

        // use first NUM_TIMED_ACCESSES addresses for sync
        for idx in 0..num_timed_accesses {
            a.mov(rax, aggressor_pairs[idx])?;
            a.mov(rcx, ptr(rax))?;
        }
        // if ((after - before) > 1000) break;
        a.rdtscp()?;
        a.sub(eax, ebx)?;
        a.cmp(eax, 1000)?;
        a.jg(while1_end)?;
        a.jmp(while1_begin)?;

        a.set_label(&mut while1_end)?;

        // part 2: perform hammering
        // initialize variables
        a.mov(rsi, total_num_activations)?;
        a.mov(edx, 0)?;

        a.set_label(&mut for_begin)?;
        a.cmp(rsi, 0)?;
        a.jle(for_end)?;

        // a map to keep track of aggressors that have been accessed before and need a fence before their next access
        let mut accessed_before = HashMap::new();

        let mut cnt_total_activations = 0;

        let offset = aggressor_pairs.len() - num_timed_accesses;
        for idx in num_timed_accesses..offset {
            let cur_addr = aggressor_pairs[idx];
            if *accessed_before.entry(cur_addr).or_insert(false) {
                // flush
                if let FlushingStrategy::LatestPossible = flushing {
                    a.mov(rax, cur_addr)?;
                    a.clflushopt(ptr(rax))?;
                    accessed_before.insert(cur_addr, false);
                }
                // fence to ensure flushing finished and defined order of aggressors is guaranteed
                if let FencingStrategy::LatestPossible = fencing {
                    a.mfence()?;
                    accessed_before.insert(cur_addr, false);
                }
            }
            // hammer
            a.mov(rax, cur_addr)?;
            a.mov(rcx, ptr(rax))?;
            a.dec(rsi)?;
            accessed_before.insert(cur_addr, true);
            cnt_total_activations += 1;

            // flush
            if let FlushingStrategy::EarliestPossible = flushing {
                a.mov(rax, cur_addr)?;
                a.clflushopt(ptr(rax))?;
                accessed_before.insert(cur_addr, false);
            }
            if sync_each_ref && (cnt_total_activations & num_acts_per_trefi) == 0 {
                let aggs = &aggressor_pairs[idx..(idx + num_timed_accesses)];
                sync_ref(aggs, &mut a)?;
            }
        }

        a.mfence()?;

        // ------- part 3: synchronize with the end  -----------------------------------------------------------------------
        let last_aggs =
            &aggressor_pairs[aggressor_pairs.len() - num_timed_accesses..aggressor_pairs.len()];
        sync_ref(last_aggs, &mut a)?;

        a.jmp(for_begin)?;
        a.set_label(&mut for_end)?;
        a.mov(rax, rdx)?;
        a.ret()?;

        let result = a.assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)?;

        let buf = &result.inner.code_buffer;

        //disas(buf, 64, 0);

        // move the assmbled code into an executable memory buffer
        let mut mem = MmapMut::map_anon(buf.len())?;

        mem.deref_mut().write_all(buf)?;

        Ok(Program {
            code: mem.make_exec()?,
            start: result.label_ip(&start)?,
        })
    }

    fn call(&self) -> u32 {
        let attacker_fn: extern "win64" fn() -> u32 =
            unsafe { mem::transmute(self.code.as_ptr().offset(self.start as isize)) };
        attacker_fn()
    }
}

fn sync_ref(aggs: &[u64], a: &mut CodeAssembler) -> Result<(), IcedError> {
    let mut wbegin = a.create_label();
    let mut wend = a.create_label();
    a.set_label(&mut wbegin)?;
    a.mfence()?;
    a.lfence()?;
    a.push(rdx)?;
    a.rdtscp()?;
    a.mov(ebx, eax)?;
    a.lfence()?;
    a.pop(rdx)?;

    for agg in aggs {
        // flush
        a.mov(rax, *agg)?;
        a.clflushopt(ptr(rax))?;
        a.mov(rax, *agg)?;
        // access
        a.mov(rax, *agg)?;
        a.mov(rcx, ptr(rax))?;

        // we do not deduct the sync aggressors from the total number of activations because the number of sync activations
        // varies for different patterns; if we deduct it from the total number of activations, we cannot ensure anymore
        // that we are hammering long enough/as many times as needed to trigger bit flips
        // assembler.dec(asmjit::x86::rsi);

        // update counter that counts the number of activation in the trailing synchronization
        a.inc(edx)?;
    }

    a.push(rdx)?;
    a.rdtscp()?;
    a.lfence()?;
    a.pop(rdx)?;
    a.sub(eax, ebx)?;
    a.cmp(eax, 1000)?;
    a.jg(wend)?;
    a.jmp(wbegin)?;

    a.set_label(&mut wend)?;

    Ok(())
}

#[allow(dead_code)]
fn disas(bytes: &[u8], bitness: u32, ip: u64) {
    let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);

    // Formatters: Masm*, Nasm*, Gas* (AT&T) and Intel* (XED).
    // For fastest code, see `SpecializedFormatter` which is ~3.3x faster. Use it if formatting
    // speed is more important than being able to re-assemble formatted instructions.
    let mut formatter = NasmFormatter::new();

    // Change some options, there are many more
    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);

    // String implements FormatterOutput
    let mut output = String::new();

    // Initialize this outside the loop because decode_out() writes to every field
    let mut instruction = Instruction::default();

    // The decoder also implements Iterator/IntoIterator so you could use a for loop:
    //      for instruction in &mut decoder { /* ... */ }
    // or collect():
    //      let instructions: Vec<_> = decoder.into_iter().collect();
    // but can_decode()/decode_out() is a little faster:
    while decoder.can_decode() {
        // There's also a decode() method that returns an instruction but that also
        // means it copies an instruction (40 bytes):
        //     instruction = decoder.decode();
        decoder.decode_out(&mut instruction);

        // Format the instruction ("disassemble" it)
        output.clear();
        formatter.format(&instruction, &mut output);

        // Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
        print!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - ip) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }
        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("  ");
            }
        }
        println!(" {}", output);
    }
}

const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;
