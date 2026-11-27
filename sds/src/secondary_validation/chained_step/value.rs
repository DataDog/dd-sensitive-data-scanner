//! Runtime value model. Values are `Copy` spans into the match, the chain's literal pool or a
//! per-call scratch buffer, so evaluating a chain does not allocate once the thread-local buffers
//! are warm.

use crate::scanner::regex_rule::RegexCacheKey;
use regex_automata::meta::Cache;
use regex_automata::util::captures::Captures;
use slotmap::SecondaryMap;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

/// Bounds `Format "{a}{a}"`-style doubling across a whole chain.
pub(crate) const MAX_SCRATCH_PER_CALL: usize = 16 * 1024;
pub(crate) const MAX_VALUE_LEN: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Match,
    Literal,
    Scratch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    pub source: Source,
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub fn of_match(input: &[u8]) -> Option<Span> {
        Some(Span {
            source: Source::Match,
            start: 0,
            end: u32::try_from(input.len()).ok()?,
        })
    }

    pub fn len(&self) -> usize {
        // `end >= start` is an invariant of every constructor; saturate rather than trust it.
        self.end.saturating_sub(self.start) as usize
    }

    /// Narrows to `[offset_start, offset_end)` relative to this span.
    pub fn narrow(&self, offset_start: usize, offset_end: usize) -> Option<Span> {
        if offset_start > offset_end || offset_end > self.len() {
            return None;
        }
        let start = self.start.checked_add(u32::try_from(offset_start).ok()?)?;
        let end = self.start.checked_add(u32::try_from(offset_end).ok()?)?;
        Some(Span {
            source: self.source,
            start,
            end,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Value {
    Bytes(Span),
    Int(u64),
}

/// The type of a slot, known at compile time so the interpreter never branches on types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotType {
    Bytes,
    Int { bits: u8 },
}

/// Failures of the value model itself. All of them are runtime errors: the input could not be
/// evaluated, which says nothing about whether the token is genuine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameFailure {
    ScratchBudgetExceeded,
    ValueTooLarge,
    /// A slot or span did not resolve. Compile-time checks make this unreachable; it is kept as a
    /// failure instead of a panic.
    DanglingReference,
}

pub(crate) struct RegexCacheEntry {
    pub cache: Cache,
    pub captures: Captures,
}

pub(crate) struct ThreadState {
    epoch: u64,
    pub scratch: Vec<u8>,
    /// One entry per regex so a `Captures` is never reused with a different `GroupInfo`. This is
    /// separate from the scanner's `regex_caches` (mutably borrowed while validators run) and from
    /// the meta regex's internal pool (which allocates a fresh `Cache` under contention).
    pub regex_caches: SecondaryMap<RegexCacheKey, RegexCacheEntry>,
}

static CACHE_EPOCH: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static THREAD_STATE: RefCell<ThreadState> = RefCell::new(ThreadState {
        epoch: CACHE_EPOCH.load(Ordering::Relaxed),
        scratch: Vec::new(),
        regex_caches: SecondaryMap::new(),
    });
}

pub(crate) fn bump_cache_epoch() {
    CACHE_EPOCH.fetch_add(1, Ordering::Relaxed);
}

/// Returns `None` when the thread-local is being torn down or is already borrowed (re-entrant
/// evaluation), so neither case can panic.
pub(crate) fn with_thread_state<T>(func: impl FnOnce(&mut ThreadState) -> T) -> Option<T> {
    THREAD_STATE
        .try_with(|cell| {
            let mut state = cell.try_borrow_mut().ok()?;
            let current_epoch = CACHE_EPOCH.load(Ordering::Relaxed);
            if state.epoch != current_epoch {
                state.epoch = current_epoch;
                state.scratch = Vec::new();
                state.regex_caches = SecondaryMap::new();
            }
            state.scratch.clear();
            Some(func(&mut state))
        })
        .ok()
        .flatten()
}

pub(crate) struct Frame<'a> {
    input: &'a [u8],
    literals: &'a [u8],
    scratch: &'a mut Vec<u8>,
    pub regex_caches: &'a mut SecondaryMap<RegexCacheKey, RegexCacheEntry>,
    slots: SmallVec<[Value; 8]>,
}

impl<'a> Frame<'a> {
    pub fn new(
        input: &'a [u8],
        literals: &'a [u8],
        scratch: &'a mut Vec<u8>,
        regex_caches: &'a mut SecondaryMap<RegexCacheKey, RegexCacheEntry>,
        slot_count: usize,
        global_match: Value,
    ) -> Self {
        let mut slots: SmallVec<[Value; 8]> = SmallVec::from_elem(Value::Int(0), slot_count);
        if let Some(first) = slots.first_mut() {
            *first = global_match;
        }
        Self {
            input,
            literals,
            scratch,
            regex_caches,
            slots,
        }
    }

    pub fn get(&self, slot: usize) -> Result<Value, FrameFailure> {
        self.slots
            .get(slot)
            .copied()
            .ok_or(FrameFailure::DanglingReference)
    }

    pub fn set(&mut self, slot: usize, value: Value) -> Result<(), FrameFailure> {
        let target = self
            .slots
            .get_mut(slot)
            .ok_or(FrameFailure::DanglingReference)?;
        *target = value;
        Ok(())
    }

    /// Stores the result of an op whose `output` is optional.
    pub fn store(&mut self, slot: Option<usize>, value: Value) -> Result<(), FrameFailure> {
        match slot {
            Some(slot) => self.set(slot, value),
            None => Ok(()),
        }
    }

    pub fn bytes(&self, span: Span) -> Result<&[u8], FrameFailure> {
        resolve(self.input, self.literals, self.scratch, span)
    }

    pub fn bytes_of(&self, value: Value) -> Result<&[u8], FrameFailure> {
        match value {
            Value::Bytes(span) => self.bytes(span),
            Value::Int(_) => Err(FrameFailure::DanglingReference),
        }
    }

    /// Splits the frame so an op can read a span while mutating the regex caches.
    pub fn bytes_and_regex_caches(
        &mut self,
        span: Span,
    ) -> Result<(&[u8], &mut SecondaryMap<RegexCacheKey, RegexCacheEntry>), FrameFailure> {
        let bytes = resolve(self.input, self.literals, self.scratch, span)?;
        Ok((bytes, self.regex_caches))
    }

    fn reserve_scratch(&mut self, len: usize) -> Result<usize, FrameFailure> {
        if len > MAX_VALUE_LEN {
            return Err(FrameFailure::ValueTooLarge);
        }
        let start = self.scratch.len();
        let new_len = start
            .checked_add(len)
            .filter(|&new_len| new_len <= MAX_SCRATCH_PER_CALL)
            .ok_or(FrameFailure::ScratchBudgetExceeded)?;
        self.scratch.resize(new_len, 0);
        Ok(start)
    }

    fn scratch_span(&self, start: usize, end: usize) -> Result<Span, FrameFailure> {
        Ok(Span {
            source: Source::Scratch,
            start: u32::try_from(start).map_err(|_| FrameFailure::ScratchBudgetExceeded)?,
            end: u32::try_from(end).map_err(|_| FrameFailure::ScratchBudgetExceeded)?,
        })
    }

    /// Reserves `max_len` scratch bytes and lets `write` fill them from `source`, returning the
    /// span of the `written` bytes. `source` may itself live in scratch: it is read from the
    /// already-committed part of the buffer while `write` fills the newly reserved tail.
    pub fn write_scratch<E: From<FrameFailure>>(
        &mut self,
        source: Option<Span>,
        max_len: usize,
        write: impl FnOnce(&[u8], &mut [u8]) -> Result<usize, E>,
    ) -> Result<Span, E> {
        let start = self.reserve_scratch(max_len)?;
        let (committed, reserved) = self
            .scratch
            .split_at_mut_checked(start)
            .ok_or(FrameFailure::DanglingReference)?;
        let source_bytes = match source {
            None => Ok(&[][..]),
            Some(span) => resolve(self.input, self.literals, committed, span),
        };
        let result = source_bytes
            .map_err(E::from)
            .and_then(|source_bytes| write(source_bytes, reserved));
        match result {
            Ok(written) if written <= max_len => {
                let end = start + written;
                self.scratch.truncate(end);
                Ok(self.scratch_span(start, end)?)
            }
            Ok(_) => {
                self.scratch.truncate(start);
                Err(FrameFailure::DanglingReference.into())
            }
            Err(failure) => {
                self.scratch.truncate(start);
                Err(failure)
            }
        }
    }

    /// Starts a value built by successive appends (`Format`). Returns its start offset.
    pub fn begin_scratch_value(&self) -> usize {
        self.scratch.len()
    }

    pub fn append_span(&mut self, value_start: usize, span: Span) -> Result<(), FrameFailure> {
        let len = span.len();
        self.check_append(value_start, len)?;
        let (start, end) = (span.start as usize, span.end as usize);
        match span.source {
            Source::Scratch => {
                if end > self.scratch.len() || start > end {
                    return Err(FrameFailure::DanglingReference);
                }
                self.scratch.extend_from_within(start..end);
            }
            Source::Match => {
                let bytes = self
                    .input
                    .get(start..end)
                    .ok_or(FrameFailure::DanglingReference)?;
                self.scratch.extend_from_slice(bytes);
            }
            Source::Literal => {
                let bytes = self
                    .literals
                    .get(start..end)
                    .ok_or(FrameFailure::DanglingReference)?;
                self.scratch.extend_from_slice(bytes);
            }
        }
        Ok(())
    }

    pub fn append_bytes(&mut self, value_start: usize, bytes: &[u8]) -> Result<(), FrameFailure> {
        self.check_append(value_start, bytes.len())?;
        self.scratch.extend_from_slice(bytes);
        Ok(())
    }

    fn check_append(&self, value_start: usize, len: usize) -> Result<(), FrameFailure> {
        let new_len = self
            .scratch
            .len()
            .checked_add(len)
            .ok_or(FrameFailure::ScratchBudgetExceeded)?;
        if new_len.saturating_sub(value_start) > MAX_VALUE_LEN {
            return Err(FrameFailure::ValueTooLarge);
        }
        if new_len > MAX_SCRATCH_PER_CALL {
            return Err(FrameFailure::ScratchBudgetExceeded);
        }
        Ok(())
    }

    pub fn end_scratch_value(&self, value_start: usize) -> Result<Span, FrameFailure> {
        self.scratch_span(value_start, self.scratch.len())
    }
}

fn resolve<'b>(
    input: &'b [u8],
    literals: &'b [u8],
    scratch: &'b [u8],
    span: Span,
) -> Result<&'b [u8], FrameFailure> {
    let buffer = match span.source {
        Source::Match => input,
        Source::Literal => literals,
        Source::Scratch => scratch,
    };
    buffer
        .get(span.start as usize..span.end as usize)
        .ok_or(FrameFailure::DanglingReference)
}
