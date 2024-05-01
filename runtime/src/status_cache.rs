use {
    log::*,
    rand::{thread_rng, Rng},
    serde::Serialize,
    solana_accounts_db::ancestors::Ancestors,
    solana_sdk::{
        clock::{Slot, MAX_RECENT_BLOCKHASHES},
        hash::Hash,
    },
    std::{
        collections::{hash_map::Entry, HashMap, HashSet},
        ops::{Deref, DerefMut},
        sync::{Arc, Mutex, RwLock, atomic::AtomicU64, atomic::Ordering},
    },
};

mod firedancer;
use firedancer::*;

pub const MAX_CACHE_ENTRIES: usize = MAX_RECENT_BLOCKHASHES;
const CACHED_KEY_SIZE: usize = 20;

// Store forks in a single chunk of memory to avoid another lookup.
pub type ForkStatus<T> = Vec<(Slot, T)>;
type KeySlice = [u8; CACHED_KEY_SIZE];
type KeyMap<T> = HashMap<KeySlice, ForkStatus<T>>;
// Map of Hash and status
pub type Status<T> = Arc<Mutex<HashMap<Hash, (usize, Vec<(KeySlice, T)>)>>>;
// A Map of hash + the highest fork it's been observed on along with
// the key offset and a Map of the key slice + Fork status for that key
type KeyStatusMap<T> = HashMap<Hash, (Slot, usize, KeyMap<T>)>;

// A map of keys recorded in each fork; used to serialize for snapshots easily.
// Doesn't store a `SlotDelta` in it because the bool `root` is usually set much later
type SlotDeltaMap<T> = HashMap<Slot, Status<T>>;

// The statuses added during a slot, can be used to build on top of a status cache or to
// construct a new one. Usually derived from a status cache's `SlotDeltaMap`
pub type SlotDelta<T> = (Slot, bool, Status<T>);

#[derive(Debug)]
struct BlockHashCache<T> {
    highest_slot: AtomicU64,
    txns: TxnMap<([u8; 20], Slot, T)>,
}

impl<T: Clone> Default for BlockHashCache<T> {
    fn default() -> Self {
        Self {
            highest_slot: AtomicU64::new(0),
            txns: TxnMap::with_capacity_hasher(524288, |(txnhash, _, _)| {
                usize::from_le_bytes(txnhash[0..8].try_into().unwrap())
            }),
        }
    }
}

#[derive(Debug)]
struct SlotDeltaCache<T> {
    blockhashes: RwLockBuckets<Hash, FiredancerVec<([u8;20], T)>, HashBits9>,
}

impl<T> Default for SlotDeltaCache<T> {
    fn default() -> Self {
        Self {
            blockhashes: RwLockBuckets::new(0),
        }
    }
}

#[derive(Debug, AbiExample)]
struct StatusCacheInner<T: Serialize + Clone> {
    cache: RwLockBuckets<Hash, BlockHashCache<T>, HashBits9>,
    roots: HashSet<Slot>,
    /// all keys seen during a fork/slot
    slot_deltas: RwLockBuckets<Slot, SlotDeltaCache<T>, HashBits9>,
}

#[derive(Debug, AbiExample)]
pub struct StatusCache<T: Serialize + Clone> {
    inner: RwLock<StatusCacheInner<T>>,
}

impl<T: Serialize + Clone> Default for StatusCache<T> {
    fn default() -> Self {
        Self {
            inner: RwLock::new(StatusCacheInner {
                cache: RwLockBuckets::new(0),
                // 0 is always a root
                roots: HashSet::from([0]),
                slot_deltas: RwLockBuckets::new(0),
            }),
        }
    }
}

impl<T: Serialize + Clone> StatusCache<T> {
    pub fn clear_slot_entries(&self, slot: Slot) {
        // let slot_deltas = self.slot_deltas.remove(&slot);
        // if let Some(slot_deltas) = slot_deltas {
        //     let slot_deltas = slot_deltas.lock().unwrap();
        //     for (blockhash, (_, key_list)) in slot_deltas.iter() {
        //         // Any blockhash that exists in self.slot_deltas must also exist
        //         // in self.cache, because in self.purge_roots(), when an entry
        //         // (b, (max_slot, _, _)) is removed from self.cache, this implies
        //         // all entries in self.slot_deltas < max_slot are also removed
        //         if let Entry::Occupied(mut o_blockhash_entries) = self.cache.entry(*blockhash) {
        //             let (_, _, all_hash_maps) = o_blockhash_entries.get_mut();
// 
        //             for (key_slice, _) in key_list {
        //                 if let Entry::Occupied(mut o_key_list) = all_hash_maps.entry(*key_slice) {
        //                     let key_list = o_key_list.get_mut();
        //                     key_list.retain(|(updated_slot, _)| *updated_slot != slot);
        //                     if key_list.is_empty() {
        //                         o_key_list.remove_entry();
        //                     }
        //                 } else {
        //                     panic!(
        //                         "Map for key must exist if key exists in self.slot_deltas, slot: {slot}"
        //                     )
        //                 }
        //             }
// 
        //             if all_hash_maps.is_empty() {
        //                 o_blockhash_entries.remove_entry();
        //             }
        //         } else {
        //             panic!("Blockhash must exist if it exists in self.slot_deltas, slot: {slot}")
        //         }
        //     }
        // }
    }

    /// Check if the key is in any of the forks in the ancestors set and
    /// with a certain blockhash.
    pub fn get_status<K: AsRef<[u8]>>(
        &self,
        key: K,
        transaction_blockhash: &Hash,
        ancestors: &Ancestors,
    ) -> Option<(Slot, T)> {
        let inner = self.inner.read().unwrap();

        let cache = match inner.cache.get(transaction_blockhash) {
            None => return None,
            Some(cache) => cache,
        };

        let txnhash = usize::from_le_bytes(key.as_ref()[0..8].try_into().unwrap());
        cache.txns.find(txnhash, |(hash, slot, res)| {
            if ancestors.contains_key(&slot) || inner.roots.contains(&slot) {
                if &key.as_ref()[0..CACHED_KEY_SIZE] == hash {
                    return true
                }
            }
            false
        }).map(|x| (x.1, x.2.clone()))
    }

    pub fn get_statuses<K: AsRef<[u8]>>(
        &self,
        items: &Vec<(&K, &Hash)>,
        ancestors: &Ancestors,
    ) -> Vec<Option<(Slot, T)>> {
        let mut processed = vec![false; items.len()];
        let mut result = vec![None; items.len()];

        let inner = self.inner.read().unwrap();

        for i in 0..items.len() {
            if processed[i] {
                continue;
            }

            let lock = match inner.cache.get(items[i].1) {
                None => continue,
                Some(cache) => cache,
            };

            for j in i..items.len() {
                if processed[j] {
                    continue;
                }

                if items[i].1 == items[j].1 {
                    processed[j] = true;
                    let txnhash = usize::from_le_bytes(items[j].0.as_ref()[0..8].try_into().unwrap());
                    result[j] = lock.txns.find(txnhash, |(hash, slot, res)| {
                        if ancestors.contains_key(&slot) || inner.roots.contains(&slot) {
                            if &items[j].0.as_ref()[0..CACHED_KEY_SIZE] == hash {
                                return true
                            }
                        }
                        false
                    }).map(|x| (x.1, x.2.clone()));
                }
            }
        }

        result
    }

    /// Search for a key with any blockhash
    /// Prefer get_status for performance reasons, it doesn't need
    /// to search all blockhashes.
    pub fn get_status_any_blockhash<K: AsRef<[u8]>>(
        &self,
        key: K,
        ancestors: &Ancestors,
    ) -> Option<(Slot, T)> {
        let inner = self.inner.read().unwrap();

        let txnhash = usize::from_le_bytes(key.as_ref()[0..8].try_into().unwrap());

        for blockhash_bucket in inner.cache.buckets() {
            let lock = blockhash_bucket.read().unwrap();
            for (_, cache) in lock.iter() {
                if let Some(found) = cache.txns.find(txnhash, |(hash, slot, res)| {
                    if ancestors.contains_key(&slot) || inner.roots.contains(&slot) {
                        if &key.as_ref()[0..CACHED_KEY_SIZE] == hash {
                            return true
                        }
                    }
                    false
                }).map(|x| (x.1, x.2.clone())) {
                    return Some(found);
                }
            }
        }

        None
    }

    fn add_root_inner(inner: &mut StatusCacheInner<T>, fork: Slot) {
        inner.roots.insert(fork);
        Self::purge_roots_inner(inner);
    }

    /// Add a known root fork.  Roots are always valid ancestors.
    /// After MAX_CACHE_ENTRIES, roots are removed, and any old keys are cleared.
    pub fn add_root(&self, fork: Slot) {
        Self::add_root_inner(self.inner.write().unwrap().deref_mut(), fork);
    }

    pub fn roots(&self) -> Vec<Slot> {
        let inner = self.inner.read().unwrap();
        inner.roots.iter().cloned().collect()
    }

    /// Insert a new key for a specific slot.
    fn insert_inner<K: AsRef<[u8]>>(inner: &StatusCacheInner<T>, transaction_blockhash: &Hash, key: K, slot: Slot, res: T) {
        let txnhash = usize::from_le_bytes(key.as_ref()[0..8].try_into().unwrap());

        let lock = inner.cache.ensure(transaction_blockhash, || BlockHashCache::default());
        lock.highest_slot.fetch_max(slot, Ordering::Relaxed);
        lock.txns.insert(txnhash, (key.as_ref().try_into().unwrap(), slot, res.clone()));
        drop(lock);

        let lock = inner.slot_deltas.ensure(&slot, || SlotDeltaCache::default());
        let mut lock2 = lock.blockhashes.ensure_write(transaction_blockhash, || FiredancerVec::with_capacity(1));
        lock2.push((key.as_ref().try_into().unwrap(), res));
    }

    pub fn insert<K: AsRef<[u8]>>(self, transaction_blockhash: &Hash, key: K, slot: Slot, res: T) {
        let inner = self.inner.read().unwrap();
        Self::insert_inner(inner.deref(), transaction_blockhash, key, slot, res);
    }

    pub fn insert_all(&self, items: Vec<(&Hash, [u8; 20], Slot, T)>) {
        let mut processed1 = vec![false; items.len()];
        let mut processed2 = vec![false; items.len()];

        let inner = self.inner.read().unwrap();

        for i in 0..items.len() {
            if processed1[i] {
                continue;
            }

            let lock = inner.cache.ensure(items[i].0, || BlockHashCache::default());
            
            for j in i..items.len() {
                if processed1[j] {
                    continue;
                }

                if items[i].0 == items[j].0 {
                    processed1[j] = true;
                    let txnhash = usize::from_le_bytes(items[j].1[0..8].try_into().unwrap());
                    lock.highest_slot.fetch_max(items[j].2, Ordering::Relaxed);
                    lock.txns.insert(txnhash, (items[j].1, items[j].2, items[j].3.clone()));
                }
            }
        }

        for i in 0..items.len() {
            if processed2[i] {
                continue;
            }

            let lock = inner.slot_deltas.ensure(&items[i].2, || SlotDeltaCache::default());
            let mut lock2 = lock.blockhashes.ensure_write(items[i].0, || FiredancerVec::with_capacity(128));

            for j in i..items.len() {
                if processed2[j] {
                    continue;
                }

                if items[i].0 == items[j].0 && items[i].2 == items[j].2{
                    processed2[j] = true;
                    let txnhash = usize::from_le_bytes(items[j].1[0..8].try_into().unwrap());
                    lock2.push((items[j].1, items[j].3.clone()));
                }
            }
        }
    }

    fn purge_roots_inner(inner: &mut StatusCacheInner<T>) {
        if inner.roots.len() > MAX_CACHE_ENTRIES {
            if let Some(min) = inner.roots.iter().min().cloned() {
                inner.roots.remove(&min);
                inner.cache.retain(|_, blockhash| blockhash.highest_slot.load(Ordering::Relaxed) > min);
                inner.slot_deltas.retain(|slot, _| *slot > min);
            }
        }
    }

    pub fn purge_roots(&self) {
        Self::purge_roots_inner(self.inner.write().unwrap().deref_mut());
    }

    /// Clear for testing
    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap();

        inner.cache.reset();
        inner.slot_deltas.reset()
    }

    /// Get the statuses for all the root slots
    pub fn root_slot_deltas(&self) -> Vec<SlotDelta<T>> {
        vec![]
        //let inner = self.inner.write().unwrap();

        //self.roots()
        //    .iter()
        //    .map(|root| {
        //        (
        //            *root,
        //            true, // <-- is_root
        //            inner.slot_deltas.get(root).cloned() read().unwrap().get(root).cloned().unwrap_or_default(),
        //        )
        //    })
        //    .collect()
    }

    // replay deltas into a status_cache allows "appending" data
    pub fn append(&self, slot_deltas: &[SlotDelta<T>]) {
        let mut inner = self.inner.write().unwrap();

        for (slot, is_root, statuses) in slot_deltas {
            statuses
                .lock()
                .unwrap()
                .iter()
                .for_each(|(tx_hash, (key_index, statuses))| {
                    for (key_slice, res) in statuses.iter() {
                        // TODO: Must preserve key_index ...
                        Self::insert_inner(inner.deref(), tx_hash, key_slice, *slot, res.clone());
                    }
            });
            if *is_root {
                Self::add_root_inner(inner.deref_mut(), *slot);
            }
        }
    }

    pub fn from_slot_deltas(slot_deltas: &[SlotDelta<T>]) -> Self {
        // play all deltas back into the status cache
        let me = Self::default();
        me.append(slot_deltas);
        me
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_sdk::{hash::hash, signature::Signature},
    };

    type BankStatusCache = StatusCache<()>;

    #[test]
    fn test_empty_has_no_sigs() {
        let sig = Signature::default();
        let blockhash = hash(Hash::default().as_ref());
        let status_cache = BankStatusCache::default();
        assert_eq!(
            status_cache.get_status(sig, &blockhash, &Ancestors::default()),
            None
        );
        assert_eq!(
            status_cache.get_status_any_blockhash(sig, &Ancestors::default()),
            None
        );
    }

    #[test]
    fn test_find_sig_with_ancestor_fork() {
        let sig = Signature::default();
        let mut status_cache = BankStatusCache::default();
        let blockhash = hash(Hash::default().as_ref());
        let ancestors = vec![(0, 1)].into_iter().collect();
        status_cache.insert(&blockhash, sig, 0, ());
        assert_eq!(
            status_cache.get_status(sig, &blockhash, &ancestors),
            Some((0, ()))
        );
        assert_eq!(
            status_cache.get_status_any_blockhash(sig, &ancestors),
            Some((0, ()))
        );
    }

    #[test]
    fn test_find_sig_without_ancestor_fork() {
        let sig = Signature::default();
        let mut status_cache = BankStatusCache::default();
        let blockhash = hash(Hash::default().as_ref());
        let ancestors = Ancestors::default();
        status_cache.insert(&blockhash, sig, 1, ());
        assert_eq!(status_cache.get_status(sig, &blockhash, &ancestors), None);
        assert_eq!(status_cache.get_status_any_blockhash(sig, &ancestors), None);
    }

    #[test]
    fn test_find_sig_with_root_ancestor_fork() {
        let sig = Signature::default();
        let mut status_cache = BankStatusCache::default();
        let blockhash = hash(Hash::default().as_ref());
        let ancestors = Ancestors::default();
        status_cache.insert(&blockhash, sig, 0, ());
        status_cache.add_root(0);
        assert_eq!(
            status_cache.get_status(sig, &blockhash, &ancestors),
            Some((0, ()))
        );
    }

    #[test]
    fn test_insert_picks_latest_blockhash_fork() {
        let sig = Signature::default();
        let mut status_cache = BankStatusCache::default();
        let blockhash = hash(Hash::default().as_ref());
        let ancestors = vec![(0, 0)].into_iter().collect();
        status_cache.insert(&blockhash, sig, 0, ());
        status_cache.insert(&blockhash, sig, 1, ());
        for i in 0..(MAX_CACHE_ENTRIES + 1) {
            status_cache.add_root(i as u64);
        }
        assert!(status_cache
            .get_status(sig, &blockhash, &ancestors)
            .is_some());
    }

    #[test]
    fn test_root_expires() {
        let sig = Signature::default();
        let mut status_cache = BankStatusCache::default();
        let blockhash = hash(Hash::default().as_ref());
        let ancestors = Ancestors::default();
        status_cache.insert(&blockhash, sig, 0, ());
        for i in 0..(MAX_CACHE_ENTRIES + 1) {
            status_cache.add_root(i as u64);
        }
        assert_eq!(status_cache.get_status(sig, &blockhash, &ancestors), None);
    }

    #[test]
    fn test_clear_signatures_sigs_are_gone() {
        let sig = Signature::default();
        let mut status_cache = BankStatusCache::default();
        let blockhash = hash(Hash::default().as_ref());
        let ancestors = Ancestors::default();
        status_cache.insert(&blockhash, sig, 0, ());
        status_cache.add_root(0);
        status_cache.clear();
        assert_eq!(status_cache.get_status(sig, &blockhash, &ancestors), None);
    }

    #[test]
    fn test_clear_signatures_insert_works() {
        let sig = Signature::default();
        let mut status_cache = BankStatusCache::default();
        let blockhash = hash(Hash::default().as_ref());
        let ancestors = Ancestors::default();
        status_cache.add_root(0);
        status_cache.clear();
        status_cache.insert(&blockhash, sig, 0, ());
        assert!(status_cache
            .get_status(sig, &blockhash, &ancestors)
            .is_some());
    }

    #[test]
    fn test_signatures_slice() {
        let sig = Signature::default();
        let mut status_cache = BankStatusCache::default();
        let blockhash = hash(Hash::default().as_ref());
        status_cache.clear();
        status_cache.insert(&blockhash, sig, 0, ());
        let (_, index, sig_map) = status_cache.cache.get(&blockhash).unwrap();
        let sig_slice: &[u8; CACHED_KEY_SIZE] =
            arrayref::array_ref![sig.as_ref(), *index, CACHED_KEY_SIZE];
        assert!(sig_map.get(sig_slice).is_some());
    }

    #[test]
    fn test_slot_deltas() {
        let sig = Signature::default();
        let mut status_cache = BankStatusCache::default();
        let blockhash = hash(Hash::default().as_ref());
        status_cache.clear();
        status_cache.insert(&blockhash, sig, 0, ());
        assert!(status_cache.roots().contains(&0));
        let slot_deltas = status_cache.root_slot_deltas();
        let cache = StatusCache::from_slot_deltas(&slot_deltas);
        assert_eq!(cache, status_cache);
        let slot_deltas = cache.root_slot_deltas();
        let cache = StatusCache::from_slot_deltas(&slot_deltas);
        assert_eq!(cache, status_cache);
    }

    #[test]
    fn test_roots_deltas() {
        let sig = Signature::default();
        let mut status_cache = BankStatusCache::default();
        let blockhash = hash(Hash::default().as_ref());
        let blockhash2 = hash(blockhash.as_ref());
        status_cache.insert(&blockhash, sig, 0, ());
        status_cache.insert(&blockhash, sig, 1, ());
        status_cache.insert(&blockhash2, sig, 1, ());
        for i in 0..(MAX_CACHE_ENTRIES + 1) {
            status_cache.add_root(i as u64);
        }
        assert_eq!(status_cache.slot_deltas.len(), 1);
        assert!(status_cache.slot_deltas.get(&1).is_some());
        let slot_deltas = status_cache.root_slot_deltas();
        let cache = StatusCache::from_slot_deltas(&slot_deltas);
        assert_eq!(cache, status_cache);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_age_sanity() {
        assert!(MAX_CACHE_ENTRIES <= MAX_RECENT_BLOCKHASHES);
    }

    #[test]
    fn test_clear_slot_signatures() {
        let sig = Signature::default();
        let mut status_cache = BankStatusCache::default();
        let blockhash = hash(Hash::default().as_ref());
        let blockhash2 = hash(blockhash.as_ref());
        status_cache.insert(&blockhash, sig, 0, ());
        status_cache.insert(&blockhash, sig, 1, ());
        status_cache.insert(&blockhash2, sig, 1, ());

        let mut ancestors0 = Ancestors::default();
        ancestors0.insert(0, 0);
        let mut ancestors1 = Ancestors::default();
        ancestors1.insert(1, 0);

        // Clear slot 0 related data
        assert!(status_cache
            .get_status(sig, &blockhash, &ancestors0)
            .is_some());
        status_cache.clear_slot_entries(0);
        assert!(status_cache
            .get_status(sig, &blockhash, &ancestors0)
            .is_none());
        assert!(status_cache
            .get_status(sig, &blockhash, &ancestors1)
            .is_some());
        assert!(status_cache
            .get_status(sig, &blockhash2, &ancestors1)
            .is_some());

        // Check that the slot delta for slot 0 is gone, but slot 1 still
        // exists
        assert!(status_cache.slot_deltas.get(&0).is_none());
        assert!(status_cache.slot_deltas.get(&1).is_some());

        // Clear slot 1 related data
        status_cache.clear_slot_entries(1);
        assert!(status_cache.slot_deltas.is_empty());
        assert!(status_cache
            .get_status(sig, &blockhash, &ancestors1)
            .is_none());
        assert!(status_cache
            .get_status(sig, &blockhash2, &ancestors1)
            .is_none());
        assert!(status_cache.cache.is_empty());
    }

    // Status cache uses a random key offset for each blockhash. Ensure that shorter
    // keys can still be used if the offset if greater than the key length.
    #[test]
    fn test_different_sized_keys() {
        let mut status_cache = BankStatusCache::default();
        let ancestors = vec![(0, 0)].into_iter().collect();
        let blockhash = Hash::default();
        for _ in 0..100 {
            let blockhash = hash(blockhash.as_ref());
            let sig_key = Signature::default();
            let hash_key = Hash::new_unique();
            status_cache.insert(&blockhash, sig_key, 0, ());
            status_cache.insert(&blockhash, hash_key, 0, ());
            assert!(status_cache
                .get_status(sig_key, &blockhash, &ancestors)
                .is_some());
            assert!(status_cache
                .get_status(hash_key, &blockhash, &ancestors)
                .is_some());
        }
    }
}
