pub const KB: usize = 1 << 10;
pub const MB: usize = 1 << 20;

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_MASK: usize = PAGE_SIZE - 1;

pub const ROW_SHIFT: usize = 13;
pub const ROW_SIZE: usize = 1 << ROW_SHIFT;

pub const CL_SIZE: usize = 64;

pub const TIMER_ROUNDS: usize = 100_000;

pub const BASE_MSB: *mut libc::c_void = 0x2000000000 as *mut libc::c_void;
