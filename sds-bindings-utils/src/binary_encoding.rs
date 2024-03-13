use dd_sds::{Encoding, Event, EventVisitor, Path, PathSegment, RuleMatch};
use std::borrow::Cow;
use std::{collections::BTreeMap, marker::PhantomData};

/// This allows scanning events that have been encoded as a byte array. In order to use this, you must
/// guarantee the following:
/// 1. Events were encoded correctly. The reference implementation is currently the Java encoding implementation.
/// 2. If the `strings_are_valid_utf8` setting is set to true, strings must be encoded in UTF-8.
///    This is not checked, and is undefined behavior if the string is not guaranteed to be UTF-8.
///    This is for _all_ strings that were encoded, including the field names of paths and the
///    actual strings being scanned.
pub struct BinaryEvent<E: Encoding> {
    // encoded bytes
    bytes: Vec<u8>,
    // storage of strings that are being mutated
    pub storage: BTreeMap<Path<'static>, (bool, String)>,
    strings_are_valid_utf8: bool,
    _phantom: PhantomData<E>,
}

impl<E: Encoding> BinaryEvent<E> {
    pub fn new(bytes: Vec<u8>, strings_are_valid_utf8: bool) -> Self {
        Self {
            bytes,
            storage: BTreeMap::new(),
            strings_are_valid_utf8,
            _phantom: PhantomData::default(),
        }
    }
}

impl<E: Encoding> Event for BinaryEvent<E> {
    type Encoding = E;

    fn visit_event<'a>(&'a mut self, visitor: &mut impl EventVisitor<'a>) {
        let mut index = 0;
        while index < self.bytes.len() {
            match self.bytes[index] {
                0 => {
                    // push field
                    let len =
                        u32::from_be_bytes(self.bytes[index + 1..index + 5].try_into().unwrap())
                            as usize;
                    index += 5;

                    let field = if self.strings_are_valid_utf8 {
                        Cow::from(unsafe {
                            std::str::from_utf8_unchecked(&self.bytes[index..(index + len)])
                        })
                    } else {
                        String::from_utf8_lossy(&self.bytes[index..(index + len)])
                    };

                    index += len;
                    visitor.push_segment(PathSegment::Field(field))
                }
                1 => {
                    // push index
                    let segment_index =
                        u32::from_be_bytes(self.bytes[index + 1..index + 5].try_into().unwrap())
                            as usize;
                    index += 5;
                    visitor.push_segment(PathSegment::Index(segment_index));
                }
                2 => {
                    // pop segment
                    visitor.pop_segment();
                    index += 1;
                }
                3 => {
                    // string content
                    let len =
                        u32::from_be_bytes(self.bytes[index + 1..index + 5].try_into().unwrap())
                            as usize;
                    index += 5;

                    let content = if self.strings_are_valid_utf8 {
                        Cow::from(unsafe {
                            std::str::from_utf8_unchecked(&self.bytes[index..(index + len)])
                        })
                    } else {
                        String::from_utf8_lossy(&self.bytes[index..(index + len)])
                    };

                    index += len;
                    let visit_result = visitor.visit_string(&content);
                    if visit_result.will_mutate && !self.storage.contains_key(&visit_result.path) {
                        self.storage.insert(
                            visit_result.path.into_static(),
                            (false, content.to_string()),
                        );
                    }
                }
                _ => panic!("invalid encoded content"),
            }
        }
    }

    fn visit_string_mut(&mut self, path: &Path, mut visit: impl FnMut(&mut String)) {
        let content = self.storage.get_mut(&path.into_static()).unwrap();
        // Mark the string as mutated (can be used for perf optimizations)
        content.0 = true;
        visit(&mut content.1);
    }
}

/// Encode a result to a byte array for efficient transfer over FFI to native code.
/// Big endian encoding.
/// 0: push field
/// 1: push index
/// 2: pop segment
/// 3: string content
/// 4: mutation (path, tag 3 / string content)
/// 5: rule match (rule index, path, replacement type, start, end, shift offset)
pub fn encode_response(
    storage: &BTreeMap<Path, (bool, String)>,
    matches: &[RuleMatch],
) -> Option<Vec<u8>> {
    if matches.is_empty() {
        return None;
    }

    let mut out = vec![];
    for (path, (mutated, content)) in storage {
        if *mutated {
            encode_mutation(&mut out, path, content);
        }
    }
    for rule_match in matches {
        encode_match(&mut out, rule_match);
    }

    Some(out)
}

fn encode_match(out: &mut Vec<u8>, rule_match: &RuleMatch) {
    out.push(5);
    out.extend((rule_match.rule_index as u32).to_be_bytes());

    // TODO: this should write directly to the output
    let path_str = rule_match.path.to_string();
    encode_bytes(out, path_str.as_bytes());

    // TODO: this should write directly to the output
    let replacement_type_str = rule_match.replacement_type.to_string();
    encode_bytes(out, replacement_type_str.as_bytes());

    out.extend((rule_match.start_index as u32).to_be_bytes());
    out.extend((rule_match.end_index_exclusive as u32).to_be_bytes());
    out.extend((rule_match.shift_offset as u32).to_be_bytes());
}

fn encode_path(out: &mut Vec<u8>, path: &Path) {
    for segment in &path.segments {
        match segment {
            PathSegment::Field(field) => {
                out.push(0);
                encode_bytes(out, field.as_bytes());
            }
            PathSegment::Index(index) => {
                out.push(1);
                out.extend((*index as u32).to_be_bytes());
            }
        }
    }
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend(bytes);
}

fn encode_mutation(out: &mut Vec<u8>, path: &Path, content: &str) {
    out.push(4);

    encode_path(out, path);
    out.push(3);
    encode_bytes(out, content.as_bytes());
}
