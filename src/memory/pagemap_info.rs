use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
};

use itertools::Itertools;
use pagemap::{MapsEntry, PageMapEntry, PageMapError};

use crate::util::PAGE_SIZE;

pub struct PageMapInfo(pub HashMap<ByMemoryRegion, Vec<(u64, PageMapEntry)>>);

impl PageMapInfo {
    pub fn load(pid: u64) -> Result<Self, PageMapError> {
        let mut pagemap = pagemap::PageMap::new(pid)?;

        let mut ret = HashMap::new();

        let maps = pagemap.maps()?;
        for map in &maps {
            let start_addr = map.memory_region().start_address();
            let k = ByMemoryRegion(map.clone());
            let mut v1 = vec![];
            if map.path() == Some("[vsyscall]") {
                // vsyscall is not resolvable on modern linux systems
                ret.insert(k, v1);
                continue;
            }
            let pmap = pagemap.pagemap_region(&map.memory_region())?;
            for (idx, pmap) in pmap.iter().enumerate() {
                v1.push((start_addr + idx as u64 * PAGE_SIZE as u64, *pmap));
            }
            ret.insert(k, v1);
        }
        Ok(Self(ret))
    }
}

impl PageMapInfo {
    pub fn maps(&self) -> Vec<&MapsEntry> {
        self.0.keys().map(|x| &x.0).collect_vec()
    }
    pub fn pagemap(&self, map: &MapsEntry) -> Option<&Vec<(u64, PageMapEntry)>> {
        self.0.get(&ByMemoryRegion(map.clone()))
    }
}

pub struct ByMemoryRegion(pub MapsEntry);

impl Hash for ByMemoryRegion {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let r = self.0.memory_region();
        (r.start_address(), r.last_address()).hash(state)
    }
}

impl PartialEq for ByMemoryRegion {
    fn eq(&self, other: &Self) -> bool {
        let r = self.0.memory_region();
        let r1 = other.0.memory_region();
        r.start_address() == r1.start_address() && r.last_address() == r1.last_address()
    }
}

impl Eq for ByMemoryRegion {}
