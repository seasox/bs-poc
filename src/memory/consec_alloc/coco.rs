use std::ffi::CString;

use anyhow::bail;

use crate::{
    memory::{ConsecBlocks, MemBlock},
    util::MB,
};

use super::ConsecAllocator;

pub struct ConsecAllocCoCo {}

impl ConsecAllocator for ConsecAllocCoCo {
    fn block_size(&self) -> usize {
        4 * MB
    }

    unsafe fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks> {
        const MOD_PATH: &str = "/dev/coco_dec_mem";
        let c_mod_path = CString::new(MOD_PATH)?;
        let fd = libc::open(c_mod_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if fd == -1 {
            bail!("Failed to open {}", MOD_PATH);
        }
        let block_size: usize = self.block_size();
        let block_count = (size as f32 / block_size as f32).ceil() as i32;
        let blocks = (0..block_count)
            .map(|_| {
                let v = libc::mmap(
                    std::ptr::null_mut(),
                    block_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE,
                    fd,
                    0,
                );
                if v == libc::MAP_FAILED {
                    bail!("Failed to mmap");
                }
                let block = MemBlock::new(v as *mut u8, 4 * MB);
                libc::memset(block.ptr as *mut libc::c_void, 0, block.len);
                //consec_checker.check(&block)?;
                Ok(block)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        libc::close(fd);
        Ok(ConsecBlocks::new(blocks))
    }
}
