use std::arch::x86_64::_mm_mfence;

use anyhow::bail;
use bs_poc::util::{KB, MB};
use lpfs::proc::pagetypeinfo::PageTypeInfo;

/// A small wrapper around pagetypeinfo() from lpfs, which is not convertible to anyhow::Result
fn pagetypeinfo() -> anyhow::Result<PageTypeInfo> {
    match lpfs::proc::pagetypeinfo::pagetypeinfo() {
        Ok(pti) => Ok(pti),
        Err(e) => bail!("{:?}", e),
    }
}

unsafe fn mmap(len: usize) -> *mut libc::c_void {
    let p = libc::mmap(
        std::ptr::null_mut(),
        len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
        -1,
        0,
    );
    assert_ne!(p, libc::MAP_FAILED, "mmap failed");
    p
}

unsafe fn _measure_num_cpu_pages() -> anyhow::Result<u64> {
    const LEN: usize = 4 * KB;
    const MAX_ALLOCS: usize = 50000;
    let mut pages = Vec::with_capacity(MAX_ALLOCS);
    for i in 0..MAX_ALLOCS {
        let pti = pagetypeinfo()?;
        let normal_before = pti
            .free_pages()
            .iter()
            .find(|(_, z, t, _)| z == "Normal" && t == "Movable")
            .unwrap();
        let p = mmap(LEN);
        let pti = pagetypeinfo()?;
        let normal_after = pti
            .free_pages()
            .iter()
            .find(|(_, z, t, _)| z == "Normal" && t == "Movable")
            .unwrap();
        pages.push(p);
        if normal_before.3 != normal_after.3 {
            for page in pages {
                libc::munmap(page, LEN);
            }
            return Ok(i as u64);
        }
    }
    bail!("experiment failed");
}

unsafe fn test_cpu_buddy_alloc() -> anyhow::Result<u64> {
    const LEN: usize = 4 * KB;
    let mut is_buddy = false;
    loop {
        let pti = pagetypeinfo()?;
        let normal_before = pti
            .free_pages()
            .iter()
            .find(|(_, z, t, _)| z == "Normal" && t == "Movable")
            .unwrap();
        let _p = mmap(LEN);
        let pti = pagetypeinfo()?;
        let normal_after = pti
            .free_pages()
            .iter()
            .find(|(_, z, t, _)| z == "Normal" && t == "Movable")
            .unwrap();
        if is_buddy && normal_before.3 == normal_after.3 {
            panic!("per cpu detected after buddy");
        }
        is_buddy = normal_before.3 != normal_after.3;
    }
}

unsafe fn _main() -> anyhow::Result<()> {
    //let (_, zone, typ, counts) = normal_before;
    //println!("{:<6} {:<12} {:?}", zone, typ, counts);
    //let bi = buddyinfo()?;
    //println!("{:?}", bi[2].free_areas());
    //print_pti(&pti);
    // allocation
    /*
    for i in 0..MAX_ALLOCS {
        let pti = pagetypeinfo()?;
        let normal_after = pti
            .free_pages()
            .iter()
            .find(|(_, z, t, _)| z == "Normal" && t == "Movable")
            .unwrap();
        let p = mmap(LEN);
        pages.append(p);
    }
    */
    //println!("-------- alloc {} --------", LEN);
    test_cpu_buddy_alloc()?;
    loop {
        const LEN: usize = 100 * MB;
        let pti = pagetypeinfo()?;
        let normal_before = pti
            .free_pages()
            .iter()
            .find(|(_, z, t, _)| z == "Normal" && t == "Movable")
            .unwrap();
        let p = libc::mmap(
            std::ptr::null_mut(),
            LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
            -1,
            0,
        );
        assert_ne!(p, libc::MAP_FAILED, "mmap failed");
        libc::memset(p, 0x11, LEN);
        _mm_mfence();
        //println!("--------    done    --------");

        let pti = pagetypeinfo()?;
        let normal_after = pti
            .free_pages()
            .iter()
            .find(|(_, z, t, _)| z == "Normal" && t == "Movable")
            .unwrap();
        //let (_, zone, typ, counts) = normal_after;
        //println!("{:<6} {:<12} {:?}", zone, typ, counts);

        let diff = diff_arrs(&normal_before.3, &normal_after.3);
        //println!("{:?}", diff);
        let bytes = low_order_bytes(&diff, 10);
        println!("{} B - {} B = {} B", LEN, bytes, LEN as i64 - bytes as i64);
        let pages = (LEN - bytes) as f32 / PAGE_SIZE as f32;
        println!("{:.02} pages", pages);

        //print_pti(&pti);
        //let bi = buddyinfo()?;
        //println!("{:?}", bi[2].free_areas());
        libc::munmap(p, LEN);
    }
}

const PAGE_SIZE: usize = 4096;

fn low_order_bytes(blocks: &[i64; 11], max_order: usize) -> usize {
    if max_order > 10 {
        panic!("Invalid order");
    }
    let mut bytes = 0;
    for i in 0..=max_order {
        bytes += blocks[i] as usize * (1 << i) * PAGE_SIZE;
    }
    bytes
}

fn diff_arrs<const S: usize>(l: &[u64; S], r: &[u64; S]) -> [i64; S] {
    let mut diffs: [i64; S] = [Default::default(); S];
    let mut i = 0;
    for (&l, &r) in l.iter().zip(r) {
        diffs[i] = l as i64 - r as i64;
        i += 1;
    }
    diffs
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
