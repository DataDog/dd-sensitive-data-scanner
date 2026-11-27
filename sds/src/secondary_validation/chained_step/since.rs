//! `since` tables: the chain version that introduced each feature a chain can reference.
//!
//! Bump policy: anything a release adds that a chain can reference (an op, an input key, an enum
//! value, an output form, a raised limit) gets `since = CHAINED_STEP_VALIDATOR_VERSION + 1` and
//! the constant is bumped. Op-specific input keys and enum values live next to their op, in tables
//! of the same shape, and are looked up through [`lookup`].

/// A feature name with the version that introduced it.
pub(crate) type SinceTable<T> = &'static [(&'static str, T, u32)];

pub(crate) const CONFIG_KEYS: SinceTable<()> = &[("version", (), 1), ("steps", (), 1)];

pub(crate) const STEP_KEYS: SinceTable<()> = &[
    ("name", (), 1),
    ("comment", (), 1),
    ("op", (), 1),
    ("input", (), 1),
    ("output", (), 1),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpKind {
    Extract,
    Split,
    Charset,
    RegexMatch,
    Format,
    Checksum,
    Encode,
    Decode,
    Compare,
}

pub(crate) const OPS: SinceTable<OpKind> = &[
    ("Extract", OpKind::Extract, 1),
    ("Split", OpKind::Split, 1),
    ("Charset", OpKind::Charset, 1),
    ("RegexMatch", OpKind::RegexMatch, 1),
    ("Format", OpKind::Format, 1),
    ("Checksum", OpKind::Checksum, 1),
    ("Encode", OpKind::Encode, 1),
    ("Decode", OpKind::Decode, 1),
    ("Compare", OpKind::Compare, 1),
];

pub(crate) fn lookup<T: Copy>(table: SinceTable<T>, name: &str) -> Option<(T, u32)> {
    table
        .iter()
        .find(|(entry_name, _, _)| *entry_name == name)
        .map(|&(_, value, since)| (value, since))
}

/// The feature that forces the highest `version` in a chain, kept for strict-validation messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FeatureRequirement {
    pub since: u32,
    pub feature: String,
    pub step_index: Option<usize>,
    pub step_name: Option<String>,
}
