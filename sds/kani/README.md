# Kani Formal Verification for SDS Inline-First Containers

This directory documents and tests the [AWS Kani](https://model-checking.github.io/kani/) bounded model-checking proofs for the inline-first container optimizations introduced in `dd-sensitive-data-scanner` (`sds`).

## What Kani Proves (Plain-English Overview)

Regular unit tests and fuzzers execute concrete sample inputs. **Kani** compiles the **exact production Rust code** in `sds/src/` into a bit-accurate logical formula (via MIR -> GotoC -> [CBMC](https://www.cprover.org/cbmc/)) and uses a SAT solver to check every possible combination of symbolic inputs (`kani::any()`) within each harness's unwind bound.

Because the proof harnesses live inside `#[cfg(kani)] mod kani_proofs` directly in the four production modules:

- **Zero translation gap**: Kani verifies the real `InternalRuleMatchSet`, `InlineSlotMap`, `BoolSet`, `contains_bit`/`set_bit`/`clear_bit`, `InlineBitBuffer`, `InlineStack`, `ScopedRuledSetEventVisitor::pop_segment`, `ExclusionCheck`, and `RuleIndexVisitor` implementations — not a separate hand-written spec.
- **Zero runtime overhead**: `#[cfg(kani)]` code is completely excluded from normal `cargo build` and `cargo test` builds.
- **Automatic memory & UB checks**: In addition to explicit functional equivalence assertions against simple reference oracles, Kani checks every array index, slice access, arithmetic overflow, unwrap, and shift inside the verified code paths.

## Verified Proof Inventory (18 Harnesses)

All 18 harnesses were verified with **Kani 0.68.0 (CBMC 6.11.0)** using `--no-default-features --features dd-sds` (`VERIFICATION:- SUCCESSFUL`, 0 failures):

| # | File | Harness | Invariant Proven |
|---|---|---|---|
| 1 | `sds/src/scanner/internal_rule_match_set.rs` | `kani_internal_rule_match_set_empty_and_sync_never_allocates_async` | Empty sync/async batches keep `is_empty() == true` and `async_matches.is_none()`; sync-only batches preserve exact order/values without ever allocating the async `AHashMap`. |
| 2 | `sds/src/scanner/internal_rule_match_set.rs` | `kani_internal_rule_match_set_some_empty_async_map_equivalence` | `is_empty()` and `into_iter()` behave identically whether `async_matches` is `None` or `Some(empty_map)`. |
| 3 | `sds/src/scanner/shared_data.rs` | `kani_inline_slot_map_capacity_one_spill_boundary` | `InlineSlotMap<u8, u8, 1, LinearSpillMap>` matches a reference array oracle across `Empty -> Inline(1) -> Spilled(2)` transitions, overwrites, and post-spill lookups/mutations. |
| 4 | `sds/src/scanner/shared_data.rs` | `kani_inline_slot_map_insert_get_overwrite_and_spill` | `InlineSlotMap<u8, u8, 2, LinearSpillMap>` matches a reference oracle across arbitrary symbolic insert/overwrite/lookup/spill sequences (all key collisions and spill orderings). |
| 5 | `sds/src/scanner/shared_data.rs` | `kani_inline_slot_map_get_or_insert_with_and_closure_skip` | `get_or_insert_with` returns the exact value, never evaluates the `make_value` closure on a key hit (both inline and after spill), and migrates every inline entry cleanly on spill. |
| 6 | `sds/src/scoped_ruleset/bool_set.rs` | `kani_bool_set_inline_equivalence` | `BoolSet` in `BoolStorage::Inline` mode (`len` 1..=8) matches a `[bool; 8]` oracle across arbitrary symbolic `get_and_set` calls, `reset()`, and post-reset reuse. |
| 7 | `sds/src/scoped_ruleset/bool_set.rs` | `kani_bool_set_heap_boundary_equivalence` | `BoolSet::new(INLINE_BOOL_CAPACITY + 1)` (`129`) uses `BoolStorage::Heap`, initializes all slots to `false`, and tracks boundary indices (`0`, `127`, `128`) without aliasing. |
| 8 | `sds/src/scoped_ruleset/bool_set.rs` | `kani_bool_set_boundary_and_heap_reset` | Exact `INLINE_BOOL_CAPACITY = 128` vs `129` storage dispatch (`Inline` vs `Heap`) and full `BoolStorage::Heap::reset()` clearing across symbolic indices. |
| 9 | `sds/src/scoped_ruleset/bool_set.rs` | `kani_bit_helpers_set_clear_and_trim_two_words` | `set_bit`, `clear_bit`, and `contains_bit` match a two-word `u64` reference mask across all bit indices `0..128`, including exact trailing-zero word trimming so `words.is_empty()` iff no bits remain set. |
| 10 | `sds/src/scoped_ruleset/bool_set.rs` | `kani_bit_helpers_partial_trim_across_256_boundary` | Clearing a high bit above the 256-rule inline word boundary (`index >= 256`) trims all trailing zero words down to the highest remaining non-zero word while preserving lower bits. |
| 11 | `sds/src/scoped_ruleset/bool_set.rs` | `kani_inline_bit_buffer_empty_to_inline` | `InlineBitBuffer::set_union_of` computes exact bitwise OR across multiple symbolic bitsets on `Empty -> Inline` transition for all `2^64` word patterns. |
| 12 | `sds/src/scoped_ruleset/bool_set.rs` | `kani_inline_bit_buffer_inline_reuse_and_clear` | Reusing an `InlineBitBuffer::Inline` buffer with a shorter union clears stale words and never leaks bits from the previous union. |
| 13 | `sds/src/scoped_ruleset/bool_set.rs` | `kani_inline_bit_buffer_inline_to_empty_clear` | Transitioning `Inline -> Empty` (zero-length union) resets `as_slice()` to empty, and a subsequent `Inline` union produces exact bits with no stale residue. |
| 14 | `sds/src/scoped_ruleset/bool_set.rs` | `kani_inline_bit_buffer_union_heap_spill` | Exceeding `INLINE_WORDS = 4` (256 rules) spills cleanly to `InlineBitBuffer::Heap`, preserves every word across both inline-sized and >4-word inputs, and handles subsequent `Heap` shrink/clear reuse. |
| 15 | `sds/src/scoped_ruleset/mod.rs` | `kani_inline_stack_push_pop_truncate_equivalence` | `InlineStack<u8, 2>` matches a reference `Vec<u8>` oracle across symbolic `push`, `pop`, `truncate`, `as_slice`, `last`, and `Empty <-> Inline <-> Heap` transitions. |
| 16 | `sds/src/scoped_ruleset/mod.rs` | `kani_inline_stack_capacity_16_spill_boundary` | Verifies the exact production `INLINE_STACK_CAPACITY = 16 -> 17` spill boundary, confirming every element `0..=16` is preserved in order across the heap spill and subsequent `truncate`/`pop`. |
| 17 | `sds/src/scoped_ruleset/mod.rs` | `kani_scoped_visitor_pop_invalidation_and_exclusion_check` | Verifies `ScopedRuledSetEventVisitor::pop_segment()` restores `tree_nodes`, `active_removal_sets`, `total_active_add_nodes`, `wildcard_segment_depth`, and sets `combined_exclusions_dirty` iff removals were popped, and verifies `ExclusionCheck::is_excluded` never leaks popped exclusions. |
| 18 | `sds/src/scoped_ruleset/mod.rs` | `kani_rule_index_visitor_dedup_wildcard_skip_and_reset` | Verifies `RuleIndexVisitor::visit_rule_indices` deduplicates overlapping rule nodes via `BoolSet`, skips `index_wildcard_match == true` duplicates, resets cleanly for subsequent strings, and matches on the `used_rule_set: None` fast path. |

## How to Reproduce

### 1. Install Kani (once)

```bash
cargo install --locked kani-verifier
cargo kani setup
```

### 2. Run a Single Harness

```bash
cd sds
CARGO_BUILD_JOBS=4 cargo kani --lib --no-default-features --features dd-sds \
    --output-format terse \
    --harness kani_inline_slot_map_capacity_one_spill_boundary
```

### 3. Run All 18 Harnesses Sequentially

```bash
cd sds
CARGO_BUILD_JOBS=4 cargo kani --lib --no-default-features --features dd-sds \
    --output-format terse
```

To verify individual harnesses one by one (recommended on laptops to keep peak memory bounded):

```bash
cd sds
for h in \
    kani_internal_rule_match_set_empty_and_sync_never_allocates_async \
    kani_internal_rule_match_set_some_empty_async_map_equivalence \
    kani_inline_slot_map_capacity_one_spill_boundary \
    kani_inline_slot_map_insert_get_overwrite_and_spill \
    kani_inline_slot_map_get_or_insert_with_and_closure_skip \
    kani_bool_set_inline_equivalence \
    kani_bool_set_heap_boundary_equivalence \
    kani_bool_set_boundary_and_heap_reset \
    kani_bit_helpers_set_clear_and_trim_two_words \
    kani_bit_helpers_partial_trim_across_256_boundary \
    kani_inline_bit_buffer_empty_to_inline \
    kani_inline_bit_buffer_inline_reuse_and_clear \
    kani_inline_bit_buffer_inline_to_empty_clear \
    kani_inline_bit_buffer_union_heap_spill \
    kani_inline_stack_push_pop_truncate_equivalence \
    kani_inline_stack_capacity_16_spill_boundary \
    kani_scoped_visitor_pop_invalidation_and_exclusion_check \
    kani_rule_index_visitor_dedup_wildcard_skip_and_reset
do
    echo "=== $h ==="
    CARGO_BUILD_JOBS=4 cargo kani --lib --no-default-features --features dd-sds \
        --output-format terse --harness "$h"
done
```

## Mutation Testing (Proving the Harnesses Catch Real Bugs)

Formal proofs are only trustworthy if they actually fail when an invariant is violated. `sds/kani/run_mutations.sh` automatically injects six realistic bugs across all four production files, runs the targeted Kani harness on each mutant, asserts that Kani reports `VERIFICATION:- FAILED` with a concrete counterexample (never a compile error), and restores every file cleanly via an `EXIT` trap:

```bash
./sds/kani/run_mutations.sh
```

| ID | File | Injected Bug | Catching Harness | Expected Result |
|---|---|---|---|---|
| M1 | `src/scanner/shared_data.rs` | `InlineSlotMap::insert` migrates only `N - 1` inline entries on spill | `kani_inline_slot_map_capacity_one_spill_boundary` | `VERIFICATION:- FAILED` (`map.len() == oracle_len`) |
| M2 | `src/scoped_ruleset/bool_set.rs` | `clear_bit` skips trailing-zero word trimming | `kani_bit_helpers_partial_trim_across_256_boundary` | `VERIFICATION:- FAILED` (`words.len() == 1`) |
| M3 | `src/scoped_ruleset/bool_set.rs` | `InlineBitBuffer::set_union_of` omits `words[..max_len].fill(0)` on inline reuse | `kani_inline_bit_buffer_inline_reuse_and_clear` | `VERIFICATION:- FAILED` (stale bit leaked) |
| M4 | `src/scoped_ruleset/mod.rs` | `ScopedRuledSetEventVisitor::pop_segment` forgets `combined_exclusions_dirty = true` | `kani_scoped_visitor_pop_invalidation_and_exclusion_check` | `VERIFICATION:- FAILED` (`combined_exclusions_dirty == popped_had_removal`) |
| M5 | `src/scoped_ruleset/mod.rs` | `RuleIndexVisitor::visit_rule_indices` drops `if !*slot` dedup check | `kani_rule_index_visitor_dedup_wildcard_skip_and_reset` | `VERIFICATION:- FAILED` (`seen[rule_index] == 1`) |
| M6 | `src/scanner/internal_rule_match_set.rs` | `InternalRuleMatchSet::push_sync_matches` omits `if matches.is_empty()` guard | `kani_internal_rule_match_set_empty_and_sync_never_allocates_async` | `VERIFICATION:- FAILED` (`set.is_empty()`) |

## Verification Design Notes & Scope

- **Deterministic spill map and hasher**: `AHashMap::new()` calls OS entropy (`getentropy`) on first seed initialization, which CBMC cannot symbolically execute as a foreign C call. `InlineSlotMap` is generic over `SpillMap<K, V>`, so Kani instantiates it with a deterministic `LinearSpillMap` backed by a fixed array `[Option<(K, V)>; 8]`, proving every `InlineSlotMap` state transition (`Empty -> Inline -> Spilled`), lookup, overwrite, and closure-skipping invariant without mocking `InlineSlotMap` itself. Harnesses that construct an `AHashMap` pass `ahash::RandomState::with_seeds(1, 2, 3, 4)`.
- **Bounded unwinds + complementary differential fuzzing**: Kani proves exact bit-level correctness for every input within each harness's unwind bound (including exact threshold transitions at `N = 1`, `N = 2`, `INLINE_STACK_CAPACITY = 16 -> 17`, `INLINE_BOOL_CAPACITY = 128 -> 129`, and `INLINE_WORDS = 4 -> 5` / 256 rules). Large multi-hundred-rule / deep-tree / real-`AHashMap` interactions are additionally validated by the crate's unit and randomized differential tests (`cargo test --lib`).
- **CBMC 6.11.0 struct-array-in-union note**: In CBMC 6.11.0, writing a multi-field struct (`NodeCounter`) via `MaybeUninit::write` into a fixed array inside a tagged enum (`InlineStack::Inline`) can lose a field write under symbolic indexing. Therefore `kani_scoped_visitor_pop_invalidation_and_exclusion_check` constructs `active_node_counter` directly via an `InlineStack::Inline` literal to verify `pop_segment()` and `ExclusionCheck`, while `InlineStack::push`/`pop`/`truncate`/spill are independently and exhaustively verified by `kani_inline_stack_push_pop_truncate_equivalence` and `kani_inline_stack_capacity_16_spill_boundary`.
