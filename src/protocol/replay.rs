use super::packet::WireGuardError;

pub const WINDOW_BITS: u64 = 1024;
const WORDS: usize = (WINDOW_BITS / 64) as usize;

pub struct ReplayWindow {
    next: u64,
    bitmap: [u64; WORDS],
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            next: 0,
            bitmap: [0; WORDS],
        }
    }

    pub fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter < self.floor() {
            return Err(WireGuardError::CounterTooOld);
        }

        if counter < self.next && self.is_set(counter) {
            return Err(WireGuardError::DuplicateCounter);
        }

        Ok(())
    }

    pub fn mark_received(&mut self, counter: u64) -> Result<(), WireGuardError> {
        self.will_accept(counter)?;

        if counter < self.next {
            self.set(counter);
            return Ok(());
        }

        if counter == u64::MAX {
            return Err(WireGuardError::CounterExhausted);
        }

        if counter - self.next >= WINDOW_BITS {
            self.bitmap = [0; WORDS];
        } else {
            let mut current = self.next;
            while current < counter {
                self.clear(current);
                current += 1;
            }
        }

        self.set(counter);
        self.next = counter + 1;
        Ok(())
    }

    fn floor(&self) -> u64 {
        self.next.saturating_sub(WINDOW_BITS)
    }

    fn index(counter: u64) -> (usize, u32) {
        let bit = counter % WINDOW_BITS;
        ((bit / 64) as usize, (bit % 64) as u32)
    }

    fn is_set(&self, counter: u64) -> bool {
        let (word, bit) = Self::index(counter);
        self.bitmap[word] & (1u64 << bit) != 0
    }

    fn set(&mut self, counter: u64) {
        let (word, bit) = Self::index(counter);
        self.bitmap[word] |= 1u64 << bit;
    }

    fn clear(&mut self, counter: u64) {
        let (word, bit) = Self::index(counter);
        self.bitmap[word] &= !(1u64 << bit);
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}
