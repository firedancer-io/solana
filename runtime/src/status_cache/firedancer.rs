use {
    log::*,
    rand::{thread_rng, Rng},
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    solana_accounts_db::ancestors::Ancestors,
    solana_sdk::{
        clock::{Slot, MAX_RECENT_BLOCKHASHES},
        hash::Hash,
    },
    std::{
        cell::UnsafeCell,
        collections::{hash_map::Entry, HashMap, HashSet},
        fmt,
        sync::{
            Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard,
            atomic::{AtomicU8, AtomicUsize, Ordering},
        },
        ops::{Deref, DerefMut},
        marker::PhantomData,
    },
};

pub trait QuickHash<K> {
    fn buckets() -> usize;
    fn hash(key: &K) -> usize;
}

#[derive(Debug)]
pub struct HashBits9;

impl QuickHash<Hash> for HashBits9 {
    fn buckets() -> usize {
        512
    }

    fn hash(key: &Hash) -> usize {
        ((key.as_ref()[0] as usize) << 1) | ((key.as_ref()[1] as usize) >> 7)
    }
}

impl QuickHash<Slot> for HashBits9 {
    fn buckets() -> usize {
        512
    }

    fn hash(key: &Slot) -> usize {
        (*key as usize) % 512
    }
}

#[derive(Debug)]
pub struct HashBits8;

impl QuickHash<[u8; 20]> for HashBits8 {
    fn buckets() -> usize {
        256
    }

    fn hash(key: &[u8; 20]) -> usize {
        key[0] as usize
    }
}

#[derive(Debug)]
pub struct RwLockBuckets<K, T, H: QuickHash<K>> {
    buckets: Vec<RwLock<FiredancerVec<(K, T)>>>,
    _phantom: PhantomData<H>,
}

impl<K, T, H> RwLockBuckets<K, T, H>
where
    K: Copy + Eq,
    H: QuickHash<K>,
{
    pub fn new(bucket_capacity: usize) -> Self {
        Self {
            buckets: (0..H::buckets()).map(|_| RwLock::new(FiredancerVec::with_capacity(bucket_capacity))).collect(),
            _phantom: PhantomData,
        }
    }

    pub fn bucket(&self, key: &K) -> &RwLock<FiredancerVec<(K, T)>> {
        &self.buckets[H::hash(key)]
    }

    pub fn buckets(&self) -> &Vec<RwLock<FiredancerVec<(K, T)>>> {
        &self.buckets
    }

    pub fn reset(&mut self) {
        self.buckets.iter().for_each(|bucket| {
            bucket.write().unwrap().len = 0;
        });
    }

    pub fn retain(&self, mut f: impl FnMut(&K, &T) -> bool) {
        for bucket in self.buckets.iter() {
            let mut bucket = bucket.write().unwrap();
            let mut i = 0;
            while i < bucket.len() {
                let item = &mut bucket[i];
                if !f(&item.0, &item.1) {
                    unsafe {
                        std::ptr::drop_in_place(bucket.data.offset(i as isize));
                        let len = bucket.len() - 1;
                        std::ptr::copy(bucket.data.offset(len as isize), bucket.data.offset(i as isize), 1);
                        bucket.len = len;
                    }
                } else {
                    i += 1;
                }
            }
        }
    }
}

pub struct RwLockBucketReadGuard<'a, K, T> {
    guard: RwLockReadGuard<'a, FiredancerVec<(K, T)>>,
    idx: usize,
}

impl<'a, K, T> Deref for RwLockBucketReadGuard<'a, K, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard[self.idx].1
    }
}

pub struct RwLockBucketWriteGuard<'a, K, T> {
    guard: RwLockWriteGuard<'a, FiredancerVec<(K, T)>>,
    idx: usize,
}

impl<'a, K, T> Deref for RwLockBucketWriteGuard<'a, K, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard[self.idx].1
    }
}

impl<'a, K, T> DerefMut for RwLockBucketWriteGuard<'a, K, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard[self.idx].1
    }
}

impl<K, T, H> RwLockBuckets<K, T, H>
where
    K: Copy + Eq + std::fmt::Debug,
    H: QuickHash<K>,
{
    pub fn get(&self, key: &K) -> Option<RwLockBucketReadGuard<K, T>> {
        let bucket = H::hash(key);
        let lock = self.buckets[bucket].read().unwrap();
        for i in 0..lock.len() {
            if lock[i].0 == *key {
                return Some(RwLockBucketReadGuard {
                    guard: lock,
                    idx: i,
                });
            }
        }
        None
    }

    pub fn ensure(&self, key: &K, default: fn() -> T) -> RwLockBucketReadGuard<K, T> {
        let bucket = H::hash(key);
        let lock = self.buckets[bucket].read().unwrap();
        let position = lock.iter().position(|(k, _)| *k == *key);
        match position {
            Some(position) => {
                RwLockBucketReadGuard {
                    guard: lock,
                    idx: position,
                }
            }
            None => {
                drop(lock);
                let mut lock = self.buckets[bucket].write().unwrap();
                let position = match lock.iter().position(|(k, _)| *k == *key) {
                    Some(position) => position,
                    None => {
                        lock.push((*key, default()));
                        lock.len() - 1
                    }
                };
                drop(lock);
                let lock = self.buckets[bucket].read().unwrap();
                RwLockBucketReadGuard {
                    guard: lock,
                    idx: position,
                }
            }
        }
    }

    pub fn ensure_write(&self, key: &K, default: fn() -> T) -> RwLockBucketWriteGuard<K, T> {
        let bucket = H::hash(key);
        let mut lock = self.buckets[bucket].write().unwrap();
        let position = lock.iter().position(|(k, _)| *k == *key);
        match position {
            Some(position) => {
                RwLockBucketWriteGuard {
                    guard: lock,
                    idx: position,
                }
            }
            None => {
                lock.push((*key, default()));
                let idx = lock.len() - 1;
                RwLockBucketWriteGuard {
                    guard: lock,
                    idx,
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct FiredancerVec<T> {
    cap: usize,
    len: usize,
    data: *mut T,
}

unsafe impl<T> Send for FiredancerVec<T> {}
unsafe impl<T> Sync for FiredancerVec<T> {}

extern "C" {
    fn fd_ext_alloc_malloc(align: usize, sz: usize) -> *mut std::ffi::c_void;
    fn fd_ext_alloc_free(data: *mut u8);
}

impl<T> FiredancerVec<T> {
    pub fn with_capacity(cap: usize) -> Self {
        let data = if cap != 0 {
            let data = unsafe { fd_ext_alloc_malloc(std::mem::align_of::<T>(), cap * std::mem::size_of::<T>()) };
            if data.is_null() {
                panic!("failed to allocate memory for status cache");
            }
            data as *mut T
        } else {
            std::ptr::null_mut() as *mut T
        };

        Self {
            cap,
            len: 0,
            data,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn push(&mut self, item: T) {
        if self.len >= self.cap {
            self.cap = usize::max(self.cap * 2, 1);
            let new_data = unsafe { fd_ext_alloc_malloc(std::mem::align_of::<T>(), self.cap * std::mem::size_of::<T>()) };
            if new_data.is_null() {
                panic!("failed to allocate memory for status cache");
            }

            if self.cap > 1 {
                unsafe {
                    std::ptr::copy_nonoverlapping(self.data, new_data as *mut T, self.len);
                    fd_ext_alloc_free(self.data as *mut u8);
                }
            }
            self.data = new_data as *mut T;
        }

        unsafe {
            std::ptr::write(self.data.offset(self.len as isize), item);
        }
        self.len += 1;
    }

    pub fn iter(&self) -> std::slice::Iter<T> {
        unsafe {
            std::slice::from_raw_parts(self.data, self.len).iter()
        }
    }

    pub fn zero(&mut self) {
        unsafe { std::slice::from_raw_parts_mut(self.data as *mut u8, self.cap()) }.fill(0);
    }
}

impl<T> Drop for FiredancerVec<T> {
    fn drop(&mut self) {
        unsafe {
            if !self.data.is_null() {
                fd_ext_alloc_free(self.data as *mut u8);
            }
        }
    }
}

impl<T> std::ops::Index<usize> for FiredancerVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        unsafe {
            &*self.data.offset(index as isize)
        }
    }
}

impl<T> std::ops::IndexMut<usize> for FiredancerVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        unsafe {
            &mut *self.data.offset(index as isize)
        }
    }
}

impl<T> Serialize for FiredancerVec<T>
where
    T: Serialize
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.iter())
    }
}

impl<'de, T> Deserialize<'de> for FiredancerVec<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VecVisitor<T> {
            marker: PhantomData<T>,
        }

        impl<'de, T> serde::de::Visitor<'de> for VecVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = FiredancerVec<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let capacity = std::cmp::min(seq.size_hint().unwrap_or(0), 2048);
                let mut values = FiredancerVec::<T>::with_capacity(capacity);

                while let Some(value) = seq.next_element()? {
                    values.push(value);
                }

                Ok(values)
            }
        }

        let visitor = VecVisitor {
            marker: PhantomData,
        };
        deserializer.deserialize_seq(visitor)
    }
}

#[derive(Debug)]
pub struct TxnMap<T> {
    inner: RwLock<(AtomicUsize, FiredancerVec<AtomicU8>, FiredancerVec<UnsafeCell<T>>)>,
    hasher: fn(&T) -> usize,
}

pub struct TxnMapReadGuard<'a, T> {
    guard: RwLockReadGuard<'a, (AtomicUsize, FiredancerVec<AtomicU8>, FiredancerVec<UnsafeCell<T>>)>,
    idx: usize,
}

impl<'a, T> Deref for TxnMapReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.guard.2[self.idx].get() }
    }
}

impl<T: Clone> TxnMap<T> {
    pub fn with_capacity_hasher(cap: usize, hasher: fn(&T) -> usize) -> Self {
        let mut status = FiredancerVec::with_capacity(cap);
        status.zero();
        Self {
            inner: RwLock::new((AtomicUsize::new(0), status, FiredancerVec::with_capacity(cap))),
            hasher,
        }
    }

    pub fn find(&self, hash: usize, apply: impl Fn(&T) -> bool) -> Option<TxnMapReadGuard<T>> {
        let lock = self.inner.read().unwrap();

        for i in 0..lock.1.cap() {
            let idx = (i + hash) % lock.1.cap();
            if lock.1[idx].load(Ordering::Relaxed) != 2 {
                break;
            }

            if apply(unsafe { &*lock.2[idx].get() }) {
                return Some(TxnMapReadGuard {
                    guard: lock,
                    idx,
                });
            }
        }

        None
    }

    fn grow_rehash(&self, lock: &mut (AtomicUsize, FiredancerVec<AtomicU8>, FiredancerVec<UnsafeCell<T>>)) {
        let mut status: FiredancerVec<AtomicU8> = FiredancerVec::with_capacity(lock.1.cap() * 2);
        status.zero();
        let mut txns: FiredancerVec<UnsafeCell<T>> = FiredancerVec::with_capacity(lock.1.cap() * 2);
        for i in 0..lock.1.cap() {
            if lock.1[i].load(Ordering::Relaxed) == 2 {
                let hash = (self.hasher)(unsafe { &*lock.2[i].get() });
                for j in 0..status.cap() {
                    if status[(j + hash) % status.cap()].load(Ordering::Relaxed) == 0 {
                        unsafe {
                            std::ptr::copy(lock.2[i].get(), (*txns.data.offset(((j + hash) % status.cap()) as isize)).get(), 1);
                        }
                        status[(j + hash) % status.cap()].store(2, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }

        lock.1 = status;
        lock.2 = txns;
    }

    pub fn insert(&self, hash: usize, value: T) {
        loop {
            let lock = self.inner.read().unwrap();
            let lock = if lock.0.load(Ordering::Relaxed) > lock.1.cap() * 9 / 10 {
                drop(lock);
                let mut lock = self.inner.write().unwrap();
                if lock.0.load(Ordering::Relaxed) > lock.1.cap() * 9 / 10 {
                    Self::grow_rehash(self, &mut lock);
                }
                drop(lock);
                self.inner.read().unwrap()
            } else {
                lock
            };

            for i in 0..lock.1.cap() {
                if lock.1[(i + hash) % lock.1.cap()].load(Ordering::Relaxed) == 0 {
                    if lock.1[(i + hash) % lock.1.cap()].compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                        unsafe { lock.2[(i + hash) % lock.1.cap()].get().write(value) };
                        lock.0.fetch_add(1, Ordering::Relaxed);
                        lock.1[(i + hash) % lock.1.cap()].store(2, Ordering::Release);
                        return;
                    }
                }
            }
        }
    }
}
