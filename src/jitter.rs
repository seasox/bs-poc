use anyhow::Result;
use iced_x86::{
    code_asm::*, BlockEncoderOptions, Decoder, DecoderOptions, Formatter, Instruction,
    NasmFormatter,
};
use libc::c_void;
use memmap2::{Mmap, MmapMut};
use serde::Deserialize;
use serde_with::DeserializeFromStr;

use core::slice;
use std::{collections::HashMap, io::Write, mem, ops::DerefMut, str::FromStr};

use crate::{memory::DRAMAddr, util::MemConfiguration};

#[derive(DeserializeFromStr, Debug, Clone)]
pub enum FlushingStrategy {
    LatestPossible,
    EarliestPossible,
}

impl FromStr for FlushingStrategy {
    type Err = String;
    fn from_str(s: &str) -> Result<FlushingStrategy, Self::Err> {
        match s {
            "LATEST_POSSIBLE" => Ok(FlushingStrategy::LatestPossible),
            "EARLIEST_POSSIBLE" => Ok(FlushingStrategy::EarliestPossible),
            _ => Err(format!("unknown strategy {}", s).into()),
        }
    }
}

#[derive(DeserializeFromStr, Debug, Clone)]
pub enum FencingStrategy {
    LatestPossible,
    EarliestPossible,
}

impl FromStr for FencingStrategy {
    type Err = String;
    fn from_str(s: &str) -> Result<FencingStrategy, Self::Err> {
        match s {
            "LATEST_POSSIBLE" => Ok(FencingStrategy::LatestPossible),
            "EARLIEST_POSSIBLE" => Ok(FencingStrategy::EarliestPossible),
            _ => Err(format!("unknown strategy {}", s).into()),
        }
    }
}

pub type JitAggressor = *mut u8;

pub trait Jitter {
    fn jit(
        &self,
        num_acts_per_trefi: u64,
        aggressor_pairs: Vec<JitAggressor>,
        log_cb: &dyn Fn(&str, JitAggressor) -> (),
    ) -> Result<Program>;
}

/*
"code_jitter":{
    "fencing_strategy":"LATEST_POSSIBLE",
    "flushing_strategy":"EARLIEST_POSSIBLE",
    "num_aggs_for_sync":2,
    "pattern_sync_each_ref":false,
    "total_activations":5000000
},
*/
#[derive(Deserialize, Debug, Clone)]
pub struct CodeJitter {
    fencing_strategy: FencingStrategy,
    flushing_strategy: FlushingStrategy,
    num_aggs_for_sync: usize,
    pattern_sync_each_ref: bool,
    pub total_activations: i64,
}

pub struct Program {
    code: Mmap,
    start: u64,
}

pub type JitFunction = unsafe extern "C" fn() -> u64;

impl Program {
    pub unsafe fn call(&self) -> u64 {
        let jit_function_ptr = self.code.as_ptr().offset(self.start as isize);
        let function_size_bytes = self.code.len() - self.start as usize;
        let jit_function_bytes =
            unsafe { slice::from_raw_parts(jit_function_ptr, function_size_bytes) };
        let jit_function: JitFunction = unsafe { mem::transmute(jit_function_bytes.as_ptr()) };
        let result = unsafe { jit_function() };
        return result;
    }
}

impl Jitter for CodeJitter {
    fn jit(
        &self,
        num_acts_per_trefi: u64,
        aggressor_pairs: Vec<JitAggressor>,
        log_cb: &dyn Fn(&str, JitAggressor) -> (),
    ) -> Result<Program> {
        let mut a = CodeAssembler::new(64)?;

        let mut start = a.create_label();
        let mut while1_begin = a.create_label();
        let mut while1_end = a.create_label();
        let mut for_begin = a.create_label();
        let mut for_end = a.create_label();

        debug!("start");

        a.set_label(&mut start)?;

        let num_timed_accesses: usize = self.num_aggs_for_sync;

        info!("num_timed_accesses={}", num_timed_accesses);
        // TODO log accesses, expected patterns, aggressors, etc.

        // part 1: synchronize with the beginning of an interval
        // warmup
        for idx in 0..num_timed_accesses {
            println!("{}", aggressor_pairs[idx] as u64);
            a.mov(rax, aggressor_pairs[idx] as u64)?;
            a.mov(rbx, ptr(rax))?;
            log_cb("ACCESS", aggressor_pairs[idx]);
        }

        a.set_label(&mut while1_begin)?;

        for idx in 0..num_timed_accesses {
            a.mov(rax, aggressor_pairs[idx] as u64)?;
            a.clflushopt(ptr(rax))?;
            log_cb("FLUSH", aggressor_pairs[idx]);
        }

        // fence memory activations, retrieve timestamp
        a.mfence()?;
        a.rdtscp()?;
        a.lfence()?;
        a.mov(ebx, eax)?;

        // use first NUM_TIMED_ACCESSES addresses for sync
        for idx in 0..num_timed_accesses {
            a.mov(rax, aggressor_pairs[idx] as u64)?;
            a.mov(rcx, ptr(rax))?;
            log_cb("ACCESS", aggressor_pairs[idx]);
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
        info!("start hammering");
        a.mov(rsi, self.total_activations)?;
        a.mov(edx, 0)?;

        a.set_label(&mut for_begin)?;
        a.cmp(rsi, 0)?;
        a.jle(for_end)?;

        // a map to keep track of aggressors that have been accessed before and need a fence before their next access
        let mut accessed_before = HashMap::new();

        let mut cnt_total_activations = 0;

        let offset = aggressor_pairs.len() - num_timed_accesses;
        for idx in num_timed_accesses..offset {
            let cur_addr = aggressor_pairs[idx] as u64;
            if *accessed_before.entry(cur_addr).or_insert(false) {
                // flush
                if let FlushingStrategy::LatestPossible = self.flushing_strategy {
                    a.mov(rax, cur_addr)?;
                    a.clflushopt(ptr(rax))?;
                    accessed_before.insert(cur_addr, false);
                    log_cb("FLUSH", aggressor_pairs[idx]);
                }
                // fence to ensure flushing finished and defined order of aggressors is guaranteed
                if let FencingStrategy::LatestPossible = self.fencing_strategy {
                    a.mfence()?;
                    accessed_before.insert(cur_addr, false);
                }
            }
            // hammer
            a.mov(rax, cur_addr)?;
            a.mov(rcx, ptr(rax))?;
            log_cb("ACCESS", aggressor_pairs[idx]);
            a.dec(rsi)?;
            accessed_before.insert(cur_addr, true);
            cnt_total_activations += 1;

            // flush
            if let FlushingStrategy::EarliestPossible = self.flushing_strategy {
                a.mov(rax, cur_addr)?;
                a.clflushopt(ptr(rax))?;
                log_cb("FLUSH", aggressor_pairs[idx]);
            }
            if self.pattern_sync_each_ref && (cnt_total_activations % num_acts_per_trefi) == 0 {
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
        a.mov(eax, edx)?;
        a.ret()?;

        let result = a.assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)?;

        let buf = &result.inner.code_buffer;

        // move the assembled code into an executable memory buffer
        let mut mem = MmapMut::map_anon(buf.len())?;

        mem.deref_mut().write_all(buf)?;

        Ok(Program {
            code: mem.make_exec()?,
            start: result.label_ip(&start)?,
        })
    }
}

fn sync_ref(aggs: &[JitAggressor], a: &mut CodeAssembler) -> Result<(), IcedError> {
    debug!("SYNC");
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

    for &agg in aggs {
        // flush
        a.mov(rax, agg as u64)?;
        a.clflushopt(ptr(rax))?;
        a.mov(rax, agg as u64)?;
        // access
        a.mov(rax, agg as u64)?;
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
pub fn disas(bytes: &[u8], bitness: u32, ip: u64) {
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
