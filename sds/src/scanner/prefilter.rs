//! Skips rules that cannot match a string, so that the scanner does not dispatch them.
//!
//! Each rule can give necessary conditions for a match: a minimum length, a minimum run of bytes
//! from a character class, a set of literals of which one must be in the content, and a set of
//! keyword literals of which one must be in the content or in the path. One pass over the string
//! then answers these conditions for all rules at once. A condition only removes a rule when the
//! rule cannot produce a match, so the output of a scan does not change.

use crate::normalization::rust_regex_adapter::convert_to_rust_regex;
use crate::proximity_keywords::{MULTI_WORD_KEYWORDS_LINK_CHARS, standardize_path_chars};
use crate::{Path, PathSegment, ProximityKeywordsConfig};
use aho_corasick::automaton::Automaton;
use aho_corasick::{Anchored, MatchKind, dfa, nfa};
use moka::sync::Cache;
use once_cell::sync::Lazy;
use regex_syntax_08::hir::literal::Extractor;
use regex_syntax_08::hir::{Class, Hir, HirKind};
use std::sync::Arc;

/// A rule set with fewer literal rules than this does not get a literal pass. The cost of the
/// pass is only repaid when it can remove several dispatches.
const MIN_LITERAL_RULES: usize = 4;
/// A rule with more alternative literals than this does not use a literal condition.
const MAX_LITERALS_PER_RULE: usize = 128;
/// Literals shorter than this appear in nearly all strings, so they remove nothing.
const MIN_LITERAL_LEN: usize = 2;
/// Classes up to this size expand to literals. This covers case variants, and it stops a digit
/// class from multiplying the number of literals.
const MAX_EXPANDED_CLASS: usize = 4;
const MAX_EXPANDED_LITERALS: usize = 64;
/// Strings at least this long take the last row of the length table. The same size caps runs.
const LEN_TABLE_SIZE: usize = 256;
/// Character classes for the run condition. These are the classes that secret and number
/// patterns use, so a rule usually gets a tight bound from one of them.
const RUN_CLASSES: usize = 8;
const RUN_CLASS_CHARS: [&[u8]; RUN_CLASSES] = [
    b"0123456789",
    b"0123456789abcdefABCDEF*",
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=",
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-",
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_+/=.*",
    b"0123456789.",
    b"0123456789-. ",
];
/// Literals are cut to this length in the automaton.
const MAX_LITERAL_LEN: usize = 6;
/// Literal sets up to this size use a DFA.
const MAX_DFA_LITERALS: usize = 2000;
/// A shorter run than this is too common to remove a rule.
const MIN_USEFUL_RUN: u32 = 4;

/// A cost model that decides when a string is too long for the passes. The unit is one eighth of a
/// nanosecond, measured on Neoverse N1. A rule costs a fixed amount per string, and an amount per
/// byte. A rule with a required literal has a fast search, so its cost per byte is low. The passes
/// cost an amount per byte. With few rules that all have a required literal, the passes cost more
/// than the rules on a long string.
const RULE_COST: usize = 800;
const LITERAL_RULE_COST_PER_BYTE: usize = 1;
const OTHER_RULE_COST_PER_BYTE: usize = 13;
const PASSES_COST_PER_BYTE: usize = 32;

/// The facts that come from a regex pattern alone. A scanner rebuild reuses them.
#[derive(Debug, PartialEq)]
pub struct RegexFacts {
    /// A string shorter than this (in bytes) cannot match.
    pub min_len: usize,
    /// When present, a match needs one of these byte strings in the content.
    pub literals: Option<Vec<Vec<u8>>>,
    /// A match needs a run of at least this many bytes from each class of `RUN_CLASS_CHARS`.
    pub min_runs: [u32; RUN_CLASSES],
}

static REGEX_FACTS: Lazy<Cache<String, Option<Arc<RegexFacts>>>> = Lazy::new(|| Cache::new(10_000));

/// The necessary conditions for a match of one rule.
#[derive(Clone, Debug, PartialEq)]
pub struct RulePrefilterSpec {
    pub regex: Arc<RegexFacts>,
    /// When present, a match needs one of `content_keywords` in the content, or one of
    /// `path_keywords` in a path field. Both hold ASCII literals, compared without ASCII case.
    pub keywords: Option<KeywordLiterals>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeywordLiterals {
    pub content_keywords: Vec<Vec<u8>>,
    pub path_keywords: Vec<Vec<u8>>,
}

impl RegexFacts {
    /// Uses the syntax options of `validation::build_regex`, so the facts describe the same
    /// regex. Returns `None` when the pattern cannot be analyzed.
    fn from_pattern(pattern: &str) -> Option<Self> {
        let converted = convert_to_rust_regex(pattern).ok()?;
        let syntax = regex_automata::util::syntax::Config::default()
            .dot_matches_new_line(false)
            .unicode(true);
        let hir = regex_automata::util::syntax::parse_with(&converted, &syntax).ok()?;
        let mut min_runs = [0; RUN_CLASSES];
        for (class, min_run) in min_runs.iter_mut().enumerate() {
            let run = class_run(&hir, class);
            let run = run.whole.unwrap_or(0).max(run.inner);
            *min_run = if run >= MIN_USEFUL_RUN { run } else { 0 };
        }
        Some(Self {
            min_len: hir.properties().minimum_len()?,
            literals: required_literals(&hir).filter(|lits| !lits.is_empty()),
            min_runs,
        })
    }
}

impl RulePrefilterSpec {
    /// Returns `None` when the pattern can not be analyzed, so the rule always runs.
    pub fn from_regex_rule(
        pattern: &str,
        proximity_keywords: Option<&ProximityKeywordsConfig>,
    ) -> Option<Self> {
        let regex = REGEX_FACTS
            .get_with_by_ref(pattern, || RegexFacts::from_pattern(pattern).map(Arc::new))?;
        Some(Self {
            regex,
            keywords: proximity_keywords
                .and_then(|config| keyword_literals(&config.included_keywords)),
        })
    }
}

/// What every match of an expression guarantees about one character class.
struct ClassRun {
    /// When present, a match has only bytes of the class, and at least this many.
    whole: Option<u32>,
    /// A match has a run of at least this many bytes of the class.
    inner: u32,
}

fn in_run_class(byte: u8, class: usize) -> bool {
    RUN_CLASS_CHARS[class].contains(&byte)
}

fn class_run(hir: &Hir, class: usize) -> ClassRun {
    let single = |all_in_class: bool| ClassRun {
        whole: all_in_class.then_some(1),
        inner: u32::from(all_in_class),
    };
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => ClassRun {
            whole: Some(0),
            inner: 0,
        },
        HirKind::Literal(literal) => {
            let bytes = &literal.0;
            let inner = bytes
                .split(|byte| !in_run_class(*byte, class))
                .map(|part| part.len() as u32)
                .max()
                .unwrap_or(0);
            ClassRun {
                whole: bytes
                    .iter()
                    .all(|byte| in_run_class(*byte, class))
                    .then_some(bytes.len() as u32),
                inner,
            }
        }
        HirKind::Class(Class::Unicode(set)) => single(set.ranges().iter().all(|range| {
            u32::from(range.end()) < 128
                && (range.start() as u8..=range.end() as u8).all(|b| in_run_class(b, class))
        })),
        HirKind::Class(Class::Bytes(set)) => single(
            set.ranges()
                .iter()
                .all(|range| (range.start()..=range.end()).all(|b| in_run_class(b, class))),
        ),
        HirKind::Capture(capture) => class_run(&capture.sub, class),
        HirKind::Repetition(rep) => {
            let sub = class_run(&rep.sub, class);
            match sub.whole {
                Some(whole) => {
                    let total = whole.saturating_mul(rep.min);
                    ClassRun {
                        whole: Some(total),
                        inner: total,
                    }
                }
                None => ClassRun {
                    whole: None,
                    inner: if rep.min >= 1 { sub.inner } else { 0 },
                },
            }
        }
        HirKind::Concat(subs) => {
            let mut current = 0u32;
            let mut best = 0u32;
            let mut all_whole = true;
            for sub in subs {
                let run = class_run(sub, class);
                match run.whole {
                    Some(whole) => {
                        current = current.saturating_add(whole);
                        best = best.max(current);
                    }
                    None => {
                        all_whole = false;
                        current = 0;
                        best = best.max(run.inner);
                    }
                }
            }
            ClassRun {
                whole: all_whole.then_some(best),
                inner: best,
            }
        }
        HirKind::Alternation(subs) => {
            let runs: Vec<_> = subs.iter().map(|sub| class_run(sub, class)).collect();
            ClassRun {
                whole: runs
                    .iter()
                    .map(|run| run.whole)
                    .collect::<Option<Vec<_>>>()
                    .and_then(|whole| whole.into_iter().min()),
                inner: runs
                    .iter()
                    .map(|run| run.whole.unwrap_or(0).max(run.inner))
                    .min()
                    .unwrap_or(0),
            }
        }
    }
}

fn is_better(new: &[Vec<u8>], old: &[Vec<u8>]) -> bool {
    let shortest = |lits: &[Vec<u8>]| lits.iter().map(Vec::len).min().unwrap_or(0);
    (shortest(new), std::cmp::Reverse(new.len())) > (shortest(old), std::cmp::Reverse(old.len()))
}

/// Byte strings of which at least one is in every match of `hir`. `None` when nothing is known.
fn required_literals(hir: &Hir) -> Option<Vec<Vec<u8>>> {
    let lits = match hir.kind() {
        HirKind::Literal(lit) => vec![lit.0.to_vec()],
        HirKind::Capture(capture) => return required_literals(&capture.sub),
        HirKind::Repetition(rep) if rep.min >= 1 => return required_literals(&rep.sub),
        HirKind::Concat(subs) => {
            let mut best: Option<Vec<Vec<u8>>> = None;
            let mut consider = |lits: Vec<Vec<u8>>| {
                if best.as_ref().is_none_or(|old| is_better(&lits, old)) {
                    best = Some(lits);
                }
            };
            for (i, sub) in subs.iter().enumerate() {
                if let Some(lits) = required_literals(sub) {
                    consider(lits);
                }
                // Prefixes of the remaining concat. This finds case-insensitive words, which
                // are a concat of small classes and not literals. A run needs one attempt, at
                // its start, because a later start only gives shorter literals.
                let starts_run = is_small_atom(sub) && (i == 0 || !is_small_atom(&subs[i - 1]));
                if starts_run {
                    let suffix = Hir::concat(subs[i..].to_vec());
                    if let Some(lits) = prefix_literals(&suffix) {
                        consider(lits);
                    }
                }
            }
            best?
        }
        HirKind::Alternation(subs) => {
            let mut all = vec![];
            for sub in subs {
                all.extend(required_literals(sub)?);
                if all.len() > MAX_LITERALS_PER_RULE {
                    return None;
                }
            }
            all
        }
        _ => return None,
    };
    let shortest = lits.iter().map(Vec::len).min()?;
    (shortest >= MIN_LITERAL_LEN && lits.len() <= MAX_LITERALS_PER_RULE).then_some(lits)
}

/// A literal or a class that literal extraction can expand.
fn is_small_atom(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Literal(_) => true,
        HirKind::Class(Class::Unicode(class)) => {
            class
                .iter()
                .map(|r| u32::from(r.end()) - u32::from(r.start()) + 1)
                .sum::<u32>()
                <= MAX_EXPANDED_CLASS as u32
        }
        HirKind::Class(Class::Bytes(class)) => {
            class
                .iter()
                .map(|r| u32::from(r.end()) - u32::from(r.start()) + 1)
                .sum::<u32>()
                <= MAX_EXPANDED_CLASS as u32
        }
        _ => false,
    }
}

fn prefix_literals(hir: &Hir) -> Option<Vec<Vec<u8>>> {
    let seq = Extractor::new()
        .limit_class(MAX_EXPANDED_CLASS)
        .limit_total(MAX_EXPANDED_LITERALS)
        .extract(hir);
    let lits = seq.literals()?;
    let shortest = lits.iter().map(|lit| lit.len()).min()?;
    if shortest < MIN_LITERAL_LEN || lits.len() > MAX_LITERALS_PER_RULE {
        return None;
    }
    Some(lits.iter().map(|lit| lit.as_bytes().to_vec()).collect())
}

/// One literal per keyword. Returns `None` when a keyword has no usable literal, because then
/// the keyword condition is unknown for the whole rule.
fn keyword_literals(keywords: &[String]) -> Option<KeywordLiterals> {
    if keywords.is_empty() {
        return None;
    }
    let mut content_keywords = vec![];
    let mut path_keywords = vec![];
    for keyword in keywords {
        let keyword = keyword.trim();
        if !keyword.is_ascii() {
            // Case folding maps only these two non-ASCII characters to ASCII letters.
            if keyword.contains(['\u{212A}', '\u{17F}']) {
                return None;
            }
            // Every other non-ASCII character needs non-ASCII text, and the pass does not use
            // keyword conditions for non-ASCII text. So this keyword needs no literal.
            continue;
        }
        // Link characters are optional between words, so only a run between them is required.
        let content = keyword
            .split(|c| MULTI_WORD_KEYWORDS_LINK_CHARS.contains(&c))
            .max_by_key(|run| run.len())?;
        // The path pattern lowercases the standardized keyword, and that adds link characters.
        let mut standardized = String::with_capacity(keyword.len() + 4);
        standardize_path_chars(keyword, |c| standardized.push(c.to_ascii_lowercase()));
        let path = standardized
            .split(|c: char| !c.is_ascii_alphanumeric())
            .max_by_key(|run| run.len())?;
        if content.is_empty() || path.is_empty() {
            return None;
        }
        content_keywords.push(content.as_bytes().to_ascii_lowercase());
        path_keywords.push(path.as_bytes().to_ascii_lowercase());
    }
    Some(KeywordLiterals {
        content_keywords,
        path_keywords,
    })
}

/// A row of rule bits for each threshold. Rows are monotonic in the value.
struct ThresholdTable {
    row_of_value: Box<[u8; LEN_TABLE_SIZE]>,
    rows: Box<[u64]>,
    words: usize,
}

impl ThresholdTable {
    /// A rule is in the row of a value when its threshold is at most that value. Thresholds are
    /// capped to the last row, which keeps the condition necessary.
    fn new(thresholds: &[u32], words: usize) -> Self {
        let cap = (LEN_TABLE_SIZE - 1) as u32;
        let mut distinct: Vec<u32> = thresholds.iter().map(|t| (*t).min(cap)).collect();
        distinct.push(0);
        distinct.sort_unstable();
        distinct.dedup();
        let mut rows = vec![0u64; distinct.len() * words];
        for (row, threshold) in distinct.iter().enumerate() {
            let bits = &mut rows[row * words..(row + 1) * words];
            for (rule, rule_threshold) in thresholds.iter().enumerate() {
                if (*rule_threshold).min(cap) <= *threshold {
                    set_bit(bits, rule);
                }
            }
        }
        let mut row_of_value = Box::new([0u8; LEN_TABLE_SIZE]);
        for (value, row) in row_of_value.iter_mut().enumerate() {
            // There are at most `LEN_TABLE_SIZE` distinct capped values, so this fits in a byte.
            *row = (distinct.partition_point(|t| *t <= value as u32) - 1) as u8;
        }
        Self {
            row_of_value,
            rows: rows.into_boxed_slice(),
            words,
        }
    }

    #[inline(always)]
    fn row(&self, value: usize) -> &[u64] {
        let row = self.row_of_value[value.min(LEN_TABLE_SIZE - 1)] as usize;
        &self.rows[row * self.words..(row + 1) * self.words]
    }
}

const fn run_masks() -> [[u8; RUN_CLASSES]; 256] {
    let mut masks = [[0u8; RUN_CLASSES]; 256];
    let mut class = 0;
    while class < RUN_CLASSES {
        let chars = RUN_CLASS_CHARS[class];
        let mut i = 0;
        while i < chars.len() {
            masks[chars[i] as usize][class] = 0xFF;
            i += 1;
        }
        class += 1;
    }
    masks
}

/// For each byte, a mask per class: all ones when the byte is in the class.
static RUN_MASKS: [[u8; RUN_CLASSES]; 256] = run_masks();

/// The longest run per class, with a cap of 255. A threshold above that is capped too.
pub(crate) fn longest_runs(content: &[u8]) -> [u8; RUN_CLASSES] {
    #[cfg(target_arch = "aarch64")]
    {
        use std::arch::aarch64::*;
        // SAFETY: NEON is part of the aarch64 baseline, and each load and store uses 8 bytes of
        // an array of 8 bytes.
        unsafe {
            let one = vdup_n_u8(1);
            let mut current = vdup_n_u8(0);
            let mut longest = vdup_n_u8(0);
            for byte in content {
                let mask = vld1_u8(RUN_MASKS[*byte as usize].as_ptr());
                current = vand_u8(vqadd_u8(current, one), mask);
                longest = vmax_u8(longest, current);
            }
            let mut out = [0u8; RUN_CLASSES];
            vst1_u8(out.as_mut_ptr(), longest);
            out
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::*;
        // SAFETY: SSE2 is part of the x86_64 baseline, and each load and store uses 8 bytes of an
        // array of 8 bytes.
        unsafe {
            let one = _mm_set1_epi8(1);
            let mut current = _mm_setzero_si128();
            let mut longest = _mm_setzero_si128();
            for byte in content {
                let mask = _mm_loadl_epi64(RUN_MASKS[*byte as usize].as_ptr().cast());
                current = _mm_and_si128(_mm_adds_epu8(current, one), mask);
                longest = _mm_max_epu8(longest, current);
            }
            let mut out = [0u8; RUN_CLASSES];
            _mm_storel_epi64(out.as_mut_ptr().cast(), longest);
            out
        }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        longest_runs_portable(content)
    }
}

#[cfg(any(test, not(any(target_arch = "aarch64", target_arch = "x86_64"))))]
pub(crate) fn longest_runs_portable(content: &[u8]) -> [u8; RUN_CLASSES] {
    let mut current = [0u8; RUN_CLASSES];
    let mut longest = [0u8; RUN_CLASSES];
    for byte in content {
        let mask = &RUN_MASKS[*byte as usize];
        for class in 0..RUN_CLASSES {
            current[class] = current[class].saturating_add(1) & mask[class];
            longest[class] = longest[class].max(current[class]);
        }
    }
    longest
}

/// An automaton over all literals. A larger literal set uses the smaller and slower form.
enum LiteralAutomaton {
    Dfa(dfa::DFA),
    Nfa(nfa::contiguous::NFA),
}

impl LiteralAutomaton {
    fn new(literals: &[Vec<u8>]) -> Option<Self> {
        if literals.len() <= MAX_DFA_LITERALS {
            let built = dfa::DFA::builder()
                .match_kind(MatchKind::Standard)
                .ascii_case_insensitive(true)
                .start_kind(aho_corasick::StartKind::Unanchored)
                .build(literals);
            built.ok().map(Self::Dfa)
        } else {
            let built = nfa::contiguous::NFA::builder()
                .match_kind(MatchKind::Standard)
                .ascii_case_insensitive(true)
                .build(literals);
            built.ok().map(Self::Nfa)
        }
    }

    /// Calls `found` for each occurrence of each literal, including overlapping ones.
    #[inline(always)]
    fn for_each_match(&self, haystack: &[u8], found: impl FnMut(usize)) {
        match self {
            Self::Dfa(automaton) => walk(automaton, haystack, found),
            Self::Nfa(automaton) => walk(automaton, haystack, found),
        }
    }
}

#[inline(always)]
fn walk<A: Automaton>(automaton: &A, haystack: &[u8], mut found: impl FnMut(usize)) {
    // An unanchored start state always exists, because the builders above create it.
    let Ok(mut state) = automaton.start_state(Anchored::No) else {
        return;
    };
    for byte in haystack {
        state = automaton.next_state(Anchored::No, state, *byte);
        if automaton.is_match(state) {
            for index in 0..automaton.match_len(state) {
                found(automaton.match_pattern(state, index).as_usize());
            }
        }
    }
}

/// What a single literal means for each rule.
#[derive(Default)]
struct LiteralUse {
    regex_rules: Box<[u32]>,
    content_keyword_rules: Box<[u32]>,
    path_keyword_rules: Box<[u32]>,
}

/// The per-scanner prefilter. It is immutable and shared between threads.
pub struct ScanPrefilter {
    words: usize,
    /// The rules with a low enough minimum length, by string length.
    len_table: ThresholdTable,
    /// The rules with a low enough minimum run, by longest run, for each class.
    run_tables: Option<Box<[ThresholdTable; RUN_CLASSES]>>,
    /// The rules with any run condition.
    needs_run: Box<[u64]>,
    /// The rules with a literal condition on the content.
    needs_regex_literal: Box<[u64]>,
    /// The rules with a keyword condition.
    needs_keyword: Box<[u64]>,
    literals: Option<LiteralAutomaton>,
    uses: Box<[LiteralUse]>,
    /// When every rule covers all paths, visiting the set bits in order is the same as visiting
    /// the rule tree of the scoped rule set.
    every_rule_covers_all_paths: bool,
    /// A longer string skips the passes and uses only the length condition.
    max_len_for_passes: usize,
}

/// Bits of a per-string pass. It is reused between the strings of one scan.
#[derive(Default)]
pub struct PrefilterScratch {
    regex_hits: Vec<u64>,
    keyword_hits: Vec<u64>,
    literal_seen: Vec<u64>,
    survivors: Vec<u64>,
}

#[inline(always)]
fn get_bit(bits: &[u64], index: usize) -> bool {
    (bits[index / 64] >> (index % 64)) & 1 == 1
}

#[inline(always)]
fn set_bit(bits: &mut [u64], index: usize) {
    bits[index / 64] |= 1 << (index % 64);
}

fn reset(bits: &mut Vec<u64>, words: usize) {
    bits.clear();
    bits.resize(words, 0);
}

impl ScanPrefilter {
    /// `specs` holds one entry per rule, in rule index order. A rule without a spec always runs.
    pub fn new(specs: &[Option<&RulePrefilterSpec>], every_rule_covers_all_paths: bool) -> Self {
        let words = specs.len().div_ceil(64);
        let mut needs_regex_literal = vec![0u64; words];
        let mut needs_keyword = vec![0u64; words];
        let literal_rules = specs
            .iter()
            .flatten()
            .filter(|s| s.regex.literals.is_some() || s.keywords.is_some())
            .count();

        let mut literals: Vec<Vec<u8>> = vec![];
        let mut uses: Vec<(Vec<u32>, Vec<u32>, Vec<u32>)> = vec![];
        let mut index = ahash::AHashMap::<Vec<u8>, usize>::new();
        let mut slot = |literal: &[u8]| -> usize {
            // A prefix of a required literal is required too, and fewer bytes make a smaller DFA.
            let key = literal[..literal.len().min(MAX_LITERAL_LEN)].to_ascii_lowercase();
            *index.entry(key.clone()).or_insert_with(|| {
                literals.push(key);
                uses.push(Default::default());
                literals.len() - 1
            })
        };
        let mut lookup: Vec<(usize, u8, u32)> = vec![];
        if literal_rules >= MIN_LITERAL_RULES {
            for (rule, spec) in specs.iter().enumerate() {
                let Some(spec) = spec else { continue };
                if let Some(lits) = &spec.regex.literals {
                    set_bit(&mut needs_regex_literal, rule);
                    for lit in lits {
                        lookup.push((slot(lit), 0, rule as u32));
                    }
                }
                if let Some(keywords) = &spec.keywords {
                    set_bit(&mut needs_keyword, rule);
                    for lit in &keywords.content_keywords {
                        lookup.push((slot(lit), 1, rule as u32));
                    }
                    for lit in &keywords.path_keywords {
                        lookup.push((slot(lit), 2, rule as u32));
                    }
                }
            }
        }
        for (literal, kind, rule) in lookup {
            let entry = &mut uses[literal];
            let list = match kind {
                0 => &mut entry.0,
                1 => &mut entry.1,
                _ => &mut entry.2,
            };
            if list.last() != Some(&rule) {
                list.push(rule);
            }
        }
        let automaton = if literals.is_empty() {
            None
        } else {
            let built = LiteralAutomaton::new(&literals);
            if built.is_none() {
                // Without an automaton no literal condition can be answered.
                needs_regex_literal.fill(0);
                needs_keyword.fill(0);
            }
            built
        };

        let min_lens: Vec<u32> = specs
            .iter()
            .map(|spec| spec.map_or(0, |s| s.regex.min_len.min(u32::MAX as usize) as u32))
            .collect();
        let min_run = |spec: &Option<&RulePrefilterSpec>, class: usize| {
            spec.map_or(0, |s| s.regex.min_runs[class])
        };
        let mut needs_run = vec![0u64; words];
        let mut run_rules = 0;
        for (rule, spec) in specs.iter().enumerate() {
            if (0..RUN_CLASSES).any(|class| min_run(spec, class) > 0) {
                set_bit(&mut needs_run, rule);
                run_rules += 1;
            }
        }
        // The pass over the bytes costs more than the literal search inside a single regex, so a
        // few rules do better without it.
        let run_tables = (run_rules >= MIN_LITERAL_RULES).then(|| {
            Box::new(std::array::from_fn(|class| {
                let thresholds: Vec<u32> = specs.iter().map(|s| min_run(s, class)).collect();
                ThresholdTable::new(&thresholds, words)
            }))
        });
        if run_tables.is_none() {
            needs_run.fill(0);
        }

        let mut literal_rule_count = 0;
        let mut other_rule_count = 0;
        for (rule, spec) in specs.iter().enumerate() {
            if get_bit(&needs_regex_literal, rule) {
                literal_rule_count += 1;
            } else if spec.is_some() && (get_bit(&needs_keyword, rule) || get_bit(&needs_run, rule))
            {
                other_rule_count += 1;
            }
        }
        let rule_cost_per_byte = literal_rule_count * LITERAL_RULE_COST_PER_BYTE
            + other_rule_count * OTHER_RULE_COST_PER_BYTE;
        let max_len_for_passes = match PASSES_COST_PER_BYTE.checked_sub(rule_cost_per_byte) {
            None | Some(0) => usize::MAX,
            Some(extra_cost_per_byte) => {
                (literal_rule_count + other_rule_count) * RULE_COST / extra_cost_per_byte
            }
        };

        Self {
            words,
            max_len_for_passes,
            len_table: ThresholdTable::new(&min_lens, words),
            run_tables,
            needs_run: needs_run.into_boxed_slice(),
            needs_regex_literal: needs_regex_literal.into_boxed_slice(),
            needs_keyword: needs_keyword.into_boxed_slice(),
            uses: uses
                .into_iter()
                .map(|(a, b, c)| LiteralUse {
                    regex_rules: a.into_boxed_slice(),
                    content_keyword_rules: b.into_boxed_slice(),
                    path_keyword_rules: c.into_boxed_slice(),
                })
                .collect(),
            literals: automaton,
            every_rule_covers_all_paths,
        }
    }

    /// Whether a rule visit can be replaced by a visit of the set bits.
    #[inline(always)]
    pub fn visits_survivors_only(&self) -> bool {
        self.every_rule_covers_all_paths
    }

    /// Runs the pass over one string. On return `scratch.survivors()` holds the rules to run.
    pub fn check_string(&self, scratch: &mut PrefilterScratch, path: &Path, content: &str) {
        let words = self.words;
        scratch.survivors.clear();
        scratch
            .survivors
            .extend_from_slice(self.len_table.row(content.len()));

        if content.len() > self.max_len_for_passes {
            return;
        }

        if let Some(run_tables) = &self.run_tables {
            let wants_runs = scratch
                .survivors
                .iter()
                .zip(self.needs_run.iter())
                .any(|(survivors, needs_run)| survivors & needs_run != 0);
            if wants_runs {
                let runs = longest_runs(content.as_bytes());
                for class in 0..RUN_CLASSES {
                    let row = run_tables[class].row(runs[class] as usize);
                    for (survivors, allowed) in scratch.survivors.iter_mut().zip(row) {
                        *survivors &= *allowed;
                    }
                }
            }
        }

        let Some(automaton) = &self.literals else {
            return;
        };
        let wants_literals = scratch
            .survivors
            .iter()
            .zip(
                self.needs_regex_literal
                    .iter()
                    .zip(self.needs_keyword.iter()),
            )
            .any(|(survivors, (regex, keyword))| survivors & (regex | keyword) != 0);
        if !wants_literals {
            return;
        }

        reset(&mut scratch.regex_hits, words);
        reset(&mut scratch.keyword_hits, words);
        reset(&mut scratch.literal_seen, self.uses.len().div_ceil(64));
        {
            let PrefilterScratch {
                regex_hits,
                keyword_hits,
                literal_seen,
                ..
            } = scratch;
            automaton.for_each_match(content.as_bytes(), |literal| {
                if get_bit(literal_seen, literal) {
                    return;
                }
                set_bit(literal_seen, literal);
                let literal_use = &self.uses[literal];
                for rule in &literal_use.regex_rules {
                    set_bit(regex_hits, *rule as usize);
                }
                for rule in &literal_use.content_keyword_rules {
                    set_bit(keyword_hits, *rule as usize);
                }
            });
        }

        // The regex literals are exact, so they apply to any text.
        let mut keyword_gap = 0;
        for i in 0..words {
            let survivors =
                scratch.survivors[i] & (!self.needs_regex_literal[i] | scratch.regex_hits[i]);
            scratch.survivors[i] = survivors;
            keyword_gap |= survivors & self.needs_keyword[i] & !scratch.keyword_hits[i];
        }
        // Without a rule that still waits for a keyword there is nothing to learn from the path.
        if keyword_gap == 0 {
            return;
        }
        // Unicode case folding maps non-ASCII characters to ASCII letters (the Kelvin sign to
        // `k`), and the keyword literals compare only ASCII case. So non-ASCII text says nothing.
        if !content.is_ascii() {
            return;
        }
        for segment in &path.segments {
            if let PathSegment::Field(field) = segment {
                if !field.is_ascii() {
                    return;
                }
                automaton.for_each_match(field.as_bytes(), |literal| {
                    for rule in &self.uses[literal].path_keyword_rules {
                        set_bit(&mut scratch.keyword_hits, *rule as usize);
                    }
                });
            }
        }
        for i in 0..words {
            scratch.survivors[i] &= !self.needs_keyword[i] | scratch.keyword_hits[i];
        }
    }
}

impl PrefilterScratch {
    /// The rules that can still match, as a bit set.
    #[inline(always)]
    pub fn survivors(&self) -> &[u64] {
        &self.survivors
    }

    #[inline(always)]
    pub fn is_survivor(&self, rule_index: usize) -> bool {
        get_bit(&self.survivors, rule_index)
    }
}
