use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi, ExecutableBuffer, AssemblyOffset};

use std::{mem};


pub trait Jitter {
    fn jit(num_aggressors_for_sync: usize, aggressor_pairs: &[usize]) -> Self;
    fn call(&self) -> bool;
}

pub struct Program {
    code: ExecutableBuffer,
    start: AssemblyOffset
}

impl Jitter for Program {
    fn jit(num_aggressors_for_sync: usize, aggressor_pairs: &[usize]) -> Program {
        let mut ops = dynasmrt::x64::Assembler::new().unwrap();

        dynasm!(ops
            ; .arch x64
            ; ->start:);

        let start = ops.offset();

        let num_timed_accesses: usize = num_aggressors_for_sync;

        // warmup
        for idx in 0..num_timed_accesses {
            dynasm!(ops
                ; .arch x64
                ; mov rax, QWORD aggressor_pairs[idx] as _
                ; mov rbx, [rax]);
        }

        dynasm!(ops
                ; .arch x64
                ; ->while1:
        );

        for idx in 0..num_timed_accesses {
            dynasm!(ops
                ; .arch x64
                ; mov rax, QWORD aggressor_pairs[idx] as _
                ; clflush [rax]);  // TODO ˝˝clflushopt not implemented: https://github.com/CensoredUsername/dynasm-rs/blob/cd35e34800ea801e510c627b7d72f45c7c0d7b35/plugin/src/arch/x64/gen_opmap.rs#L257
        }

        // fence memory activations, retrieve timestamp
        dynasm!(ops
            ; .arch x64
            ; mfence
            ; rdtsc
            ; lfence
            ; mov ebx, eax);

        dynasm!(ops
            ; .arch x64
            ; ret);

        let buf = ops.finalize().unwrap();

        return Program {
            code: buf,
            start: start
        }
    }

    fn call(&self) -> bool {
            let attacker_fn: extern "win64" fn() -> bool = unsafe { mem::transmute(self.code.ptr(self.start)) };
            attacker_fn()
    }
}