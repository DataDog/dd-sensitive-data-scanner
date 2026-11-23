#!/usr/bin/env bash
# Mutation-testing driver for the SDS Kani verification suite.
#
# Injects six concrete, realistic bugs across all four modified production files,
# runs the corresponding Kani harness sequentially against the real crate code,
# asserts that Kani reports `VERIFICATION:- FAILED` with a failing check (not a
# compile error), and always restores the original file contents on exit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BACKUP_DIR="$(mktemp -d)"

restore_all() {
    if [[ -d "${BACKUP_DIR}" ]]; then
        for bak in "${BACKUP_DIR}"/*.bak; do
            [[ -e "${bak}" ]] || continue
            local rel
            rel="$(cat "${bak}.path")"
            cp "${bak}" "${SDS_DIR}/${rel}"
        done
        rm -rf "${BACKUP_DIR}"
    fi
}
trap restore_all EXIT INT TERM

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"

run_mutation() {
    local id="$1"
    local description="$2"
    local rel_path="$3"
    local find_str="$4"
    local replace_str="$5"
    local harness="$6"

    local target="${SDS_DIR}/${rel_path}"
    local bak="${BACKUP_DIR}/${id}.bak"
    cp "${target}" "${bak}"
    printf '%s' "${rel_path}" > "${bak}.path"

    python3 - "${target}" "${find_str}" "${replace_str}" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "r", encoding="utf-8") as f:
    src = f.read()
count = src.count(old)
if count != 1:
    sys.stderr.write(f"ERROR: expected exactly 1 match in {path}, found {count}\n")
    sys.exit(2)
with open(path, "w", encoding="utf-8") as f:
    f.write(src.replace(old, new, 1))
PY

    echo "=== [${id}] ${description} ==="
    echo "  File:    ${rel_path}"
    echo "  Harness: ${harness}"

    local out_file="${BACKUP_DIR}/${id}.out"
    set +e
    (
        cd "${SDS_DIR}" && \
        cargo kani --lib --no-default-features --features dd-sds \
            --output-format terse --harness "${harness}" \
            > "${out_file}" 2>&1
    )
    local rc=$?
    set -e

    # Immediately restore before checking output so the tree stays clean.
    cp "${bak}" "${target}"
    rm -f "${bak}" "${bak}.path"

    if ! grep -q "VERIFICATION:- FAILED" "${out_file}"; then
        echo "  RESULT: UNEXPECTED (rc=${rc}, expected VERIFICATION:- FAILED)"
        tail -n 40 "${out_file}"
        exit 1
    fi

    local failed_line
    failed_line="$(grep -E "Failed Checks:|Verification Time:" "${out_file}" || true)"
    echo "  RESULT: CAUGHT (VERIFICATION:- FAILED)"
    while IFS= read -r line; do
        [[ -n "${line}" ]] && echo "  ${line}"
    done <<< "${failed_line}"
    echo
}

run_mutation \
    "M1" \
    "InlineSlotMap::insert drops last inline entry when spilling to heap" \
    "src/scanner/shared_data.rs" \
    "                let mut spilled = S::with_capacity(N + 1);
                for slot in entries.iter_mut() {" \
    "                let mut spilled = S::with_capacity(N + 1);
                for slot in entries.iter_mut().take(N - 1) {" \
    "kani_inline_slot_map_capacity_one_spill_boundary"

run_mutation \
    "M2" \
    "clear_bit skips trailing-zero word trimming" \
    "src/scoped_ruleset/bool_set.rs" \
    "        // Trim trailing zero words so \`words.is_empty()\` remains exact for \"no bits set\".
        while words.last() == Some(&0) {
            words.pop();
        }" \
    "        // MUTATION: skip trailing zero word trimming.
        if false {
            while words.last() == Some(&0) {
                words.pop();
            }
        }" \
    "kani_bit_helpers_partial_trim_across_256_boundary"

run_mutation \
    "M3" \
    "InlineBitBuffer::set_union_of skips clearing stale inline words on reuse" \
    "src/scoped_ruleset/bool_set.rs" \
    "                Self::Inline { words, len } => {
                    words[..max_len].fill(0);
                    *len = max_len;" \
    "                Self::Inline { words, len } => {
                    // MUTATION: omit words[..max_len].fill(0);
                    *len = max_len;" \
    "kani_inline_bit_buffer_inline_reuse_and_clear"

run_mutation \
    "M4" \
    "ScopedRuledSetEventVisitor::pop_segment forgets to mark combined_exclusions_dirty" \
    "src/scoped_ruleset/mod.rs" \
    "        if node_counter.active_removal_count > 0 {
            self.active_removal_sets.truncate(
                self.active_removal_sets.len() - node_counter.active_removal_count as usize,
            );
            self.combined_exclusions_dirty = true;
        }" \
    "        if node_counter.active_removal_count > 0 {
            self.active_removal_sets.truncate(
                self.active_removal_sets.len() - node_counter.active_removal_count as usize,
            );
            // MUTATION: omit self.combined_exclusions_dirty = true;
        }" \
    "kani_scoped_visitor_pop_invalidation_and_exclusion_check"

run_mutation \
    "M5" \
    "RuleIndexVisitor::visit_rule_indices drops dedup check on used_rule_set" \
    "src/scoped_ruleset/mod.rs" \
    "                    let slot = &mut used[rule_index];
                    if !*slot {
                        *slot = true;
                        (visit)(rule_index)?;
                    }" \
    "                    let slot = &mut used[rule_index];
                    *slot = true;
                    (visit)(rule_index)?;" \
    "kani_rule_index_visitor_dedup_wildcard_skip_and_reset"

run_mutation \
    "M6" \
    "InternalRuleMatchSet::push_sync_matches pushes empty match vectors" \
    "src/scanner/internal_rule_match_set.rs" \
    "    pub fn push_sync_matches(&mut self, path: &Path, matches: Vec<InternalRuleMatch<E>>) {
        if matches.is_empty() {
            return;
        }
        self.sync_matches.push((path.into_static(), matches));
    }" \
    "    pub fn push_sync_matches(&mut self, path: &Path, matches: Vec<InternalRuleMatch<E>>) {
        // MUTATION: omit empty check.
        self.sync_matches.push((path.into_static(), matches));
    }" \
    "kani_internal_rule_match_set_empty_and_sync_never_allocates_async"

echo "ALL 6/6 MUTATIONS CAUGHT BY KANI (VERIFICATION:- FAILED)."
