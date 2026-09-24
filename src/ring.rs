//! Single-producer/single-consumer queues and dispatcher-owned packet buffers.
//!
//! A buffer handle moves through the queues with exclusive ownership. Its
//! storage stays in the pool, so moving a packet between dispatcher and worker
//! does not copy packet bytes.

use std::cell::{Cell, UnsafeCell};
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct RingInner<T> {
    slots: Box<[UnsafeCell<MaybeUninit<T>>]>,
    head: AtomicUsize,
    tail: AtomicUsize,
}

// Only the producer writes an uninitialized slot and only the consumer reads
// it after observing head with Acquire ordering.
unsafe impl<T: Send> Send for RingInner<T> {}
unsafe impl<T: Send> Sync for RingInner<T> {}

impl<T> Drop for RingInner<T> {
    fn drop(&mut self) {
        let tail = *self.tail.get_mut();
        let head = *self.head.get_mut();
        for offset in 0..head.wrapping_sub(tail) {
            let slot = tail.wrapping_add(offset) % self.slots.len();
            // The queue is being destroyed after its last endpoint dropped.
            unsafe { self.slots[slot].get_mut().assume_init_drop() };
        }
    }
}

/// The producer half of an SPSC ring. It is intentionally not cloneable.
pub struct Producer<T> {
    inner: Arc<RingInner<T>>,
}

/// The consumer half of an SPSC ring. It is intentionally not cloneable.
pub struct Consumer<T> {
    inner: Arc<RingInner<T>>,
}

/// Creates a bounded, lock-free SPSC ring with exactly `capacity` usable slots.
pub fn spsc_ring<T: Send>(capacity: usize) -> (Producer<T>, Consumer<T>) {
    assert!(capacity > 0, "an SPSC ring must have at least one slot");
    let slots = (0..capacity)
        .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let inner = Arc::new(RingInner {
        slots,
        head: AtomicUsize::new(0),
        tail: AtomicUsize::new(0),
    });
    (
        Producer {
            inner: Arc::clone(&inner),
        },
        Consumer { inner },
    )
}

impl<T> Producer<T> {
    /// Whether no value is currently visible to the consumer.
    pub fn is_empty(&self) -> bool {
        self.inner.head.load(Ordering::Relaxed) == self.inner.tail.load(Ordering::Acquire)
    }

    /// Attempts to enqueue a value. On a full ring, returns ownership to caller.
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        let head = self.inner.head.load(Ordering::Relaxed);
        let tail = self.inner.tail.load(Ordering::Acquire);
        let capacity = self.inner.slots.len();
        if head.wrapping_sub(tail) >= capacity {
            return Err(value);
        }
        let slot = head % capacity;
        // The consumer cannot access this slot until the release store below.
        unsafe { (*self.inner.slots[slot].get()).write(value) };
        self.inner
            .head
            .store(head.wrapping_add(1), Ordering::Release);
        Ok(())
    }
}

impl<T> Consumer<T> {
    /// Removes the next value, or returns `None` when the ring is empty.
    pub fn try_pop(&mut self) -> Option<T> {
        let tail = self.inner.tail.load(Ordering::Relaxed);
        let head = self.inner.head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let slot = tail % self.inner.slots.len();
        // The producer's release store made this initialized value visible.
        let value = unsafe { (*self.inner.slots[slot].get()).assume_init_read() };
        self.inner
            .tail
            .store(tail.wrapping_add(1), Ordering::Release);
        Some(value)
    }
}

struct PoolInner {
    buffers: Box<[UnsafeCell<Box<[u8]>>]>,
}

// Each slot has one live BufHandle at a time; the dispatcher free list only
// receives a slot back after the previous handle has been consumed.
unsafe impl Send for PoolInner {}
unsafe impl Sync for PoolInner {}

/// A fixed-size pool whose free list is owned by the dispatcher.
pub struct BufPool {
    inner: Arc<PoolInner>,
    free: Vec<usize>,
    headroom: usize,
}

/// Exclusive ownership of one pool slot. This value is movable across threads,
/// but cannot be shared or cloned while its bytes are being processed.
pub struct BufHandle {
    inner: Arc<PoolInner>,
    slot: usize,
    len: usize,
    _not_sync: std::marker::PhantomData<Cell<()>>,
}

// The handle owns its slot exclusively. `Cell` in the marker prevents Sync.
unsafe impl Send for BufHandle {}

impl BufPool {
    /// Allocates `slot_count` stable packet buffers of `buffer_size` bytes.
    pub fn new(slot_count: usize, buffer_size: usize, headroom: usize) -> Self {
        assert!(slot_count > 0 && buffer_size > headroom);
        let buffers = (0..slot_count)
            .map(|_| UnsafeCell::new(vec![0; buffer_size].into_boxed_slice()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let free = (0..slot_count).rev().collect();
        Self {
            inner: Arc::new(PoolInner { buffers }),
            free,
            headroom,
        }
    }

    /// Reserves a free slot for an incoming packet or `None` when exhausted.
    pub fn allocate(&mut self) -> Option<BufHandle> {
        let slot = self.free.pop()?;
        Some(BufHandle {
            inner: Arc::clone(&self.inner),
            slot,
            len: 0,
            _not_sync: std::marker::PhantomData,
        })
    }

    /// Returns a completed slot to the dispatcher's free list.
    pub fn recycle(&mut self, handle: BufHandle) {
        assert!(
            Arc::ptr_eq(&self.inner, &handle.inner),
            "buffer belongs to another pool"
        );
        assert!(handle.slot < self.inner.buffers.len());
        self.free.push(handle.slot);
        drop(handle);
    }

    /// Number of currently free slots.
    pub fn available(&self) -> usize {
        self.free.len()
    }

    /// Bytes reserved before the packet start in buffers from this pool.
    pub fn headroom(&self) -> usize {
        self.headroom
    }
}

impl BufHandle {
    /// Total capacity of this slot.
    pub fn capacity(&self) -> usize {
        unsafe { (&*self.inner.buffers[self.slot].get()).len() }
    }

    /// Current packet length recorded in this handle.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether this handle currently describes an empty packet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Records the packet length after a read or packet transformation.
    pub fn set_len(&mut self, len: usize) {
        assert!(
            len <= self.capacity(),
            "packet length exceeds buffer capacity"
        );
        self.len = len;
    }

    /// Reads initialized packet bytes.
    pub fn bytes(&self) -> &[u8] {
        let buffer = unsafe { &*self.inner.buffers[self.slot].get() };
        &buffer[..self.len]
    }

    /// Mutably accesses the whole slot for a direct socket or TUN read.
    pub fn storage_mut(&mut self) -> &mut [u8] {
        let buffer = unsafe { &mut *self.inner.buffers[self.slot].get() };
        buffer
    }

    /// Mutably accesses the currently recorded packet.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.storage_mut()[..len]
    }

    /// Returns the slot number for diagnostics and pool ownership checks.
    pub fn slot(&self) -> usize {
        self.slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// A full ring leaves the value with its producer and reuses slots in order.
    #[test]
    fn a_full_ring_returns_values_and_reuses_slots_in_fifo_order() {
        let (mut producer, mut consumer) = spsc_ring(2);
        assert_eq!(producer.try_push(1), Ok(()));
        assert_eq!(producer.try_push(2), Ok(()));
        assert_eq!(producer.try_push(3), Err(3));
        assert_eq!(consumer.try_pop(), Some(1));
        assert_eq!(producer.try_push(3), Ok(()));
        assert_eq!(consumer.try_pop(), Some(2));
        assert_eq!(consumer.try_pop(), Some(3));
        assert_eq!(consumer.try_pop(), None);
    }

    /// A queue can hand exclusively owned values between threads.
    #[test]
    fn an_spsc_ring_transfers_values_between_threads() {
        let (mut producer, mut consumer) = spsc_ring(32);
        let writer = thread::spawn(move || {
            for n in 0..10_000usize {
                let mut value = n;
                loop {
                    match producer.try_push(value) {
                        Ok(()) => break,
                        Err(returned) => {
                            value = returned;
                            thread::yield_now();
                        }
                    }
                }
            }
        });
        for expected in 0..10_000usize {
            loop {
                if let Some(value) = consumer.try_pop() {
                    assert_eq!(value, expected);
                    break;
                }
                thread::yield_now();
            }
        }
        writer.join().unwrap();
    }

    /// Pool slots are exclusive and become reusable only after dispatcher recycle.
    #[test]
    fn a_buffer_slot_returns_to_the_pool_after_recycling() {
        let mut pool = BufPool::new(1, 128, 16);
        let mut handle = pool.allocate().unwrap();
        handle.storage_mut()[16..20].copy_from_slice(b"data");
        handle.set_len(20);
        assert_eq!(&handle.bytes()[16..], b"data");
        assert!(pool.allocate().is_none());
        pool.recycle(handle);
        assert_eq!(pool.available(), 1);
        assert_eq!(pool.allocate().unwrap().slot(), 0);
    }
}
