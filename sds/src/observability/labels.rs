use metrics::{IntoLabels, Label, SharedString};
use std::fmt;

use serde::de::{Deserializer, Error, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize, Serializer};

/// Holder of multiple [Label] providing some methods to easily clone and adds new labels in it.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Labels(Vec<Label>);

impl Labels {
    /// Clone the actual [Labels] with additional key-value labels
    pub fn clone_with_labels(&self, additional_labels: Labels) -> Labels {
        let mut tags = self.0.clone();
        tags.extend(additional_labels.into_labels());
        Labels(tags)
    }

    pub fn new(
        labels: &[(
            impl Into<SharedString> + Clone,
            impl Into<SharedString> + Clone,
        )],
    ) -> Self {
        Labels(labels.iter().map(Label::from).collect())
    }

    pub const fn empty() -> Self {
        Labels(vec![])
    }
}

impl Default for Labels {
    fn default() -> Self {
        Self::empty()
    }
}

impl IntoLabels for Labels {
    fn into_labels(self) -> Vec<Label> {
        self.0
    }
}

impl<'de> Deserialize<'de> for Labels {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LabelsVisitor;

        impl<'de> Visitor<'de> for LabelsVisitor {
            type Value = Labels;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("List of pairs of strings")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut label_list: Vec<(String, String)> =
                    Vec::with_capacity(seq.size_hint().unwrap_or(0));

                // While there are elements remaining in the input, add them
                // into our list.
                while let Some(element) = seq.next_element::<Vec<String>>()? {
                    if element.len() < 2 {
                        return Err(Error::custom(format!(
                            "list `{:?}` contains a single element, two elements (key and value) are required",
                            element
                        )));
                    }
                    if element.len() > 2 {
                        return Err(Error::custom(format!(
                            "list `{:?}` contains more than two elements, only two elements (key and value) are allowed",
                            element
                        )));
                    }
                    label_list.push((
                        element.first().unwrap().clone(),
                        element.last().unwrap().clone(),
                    ))
                }

                Ok(Labels::new(&label_list))
            }
        }
        deserializer.deserialize_seq(LabelsVisitor)
    }
}

impl Serialize for Labels {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for label in self.clone().into_labels() {
            seq.serialize_element(&vec![label.key(), label.value()])?;
        }
        seq.end()
    }
}

#[cfg(test)]
mod test {
    use crate::observability::labels::Labels;
    use metrics::{IntoLabels, Label};

    #[test]
    fn test_clone_labels() {
        let labels = Labels::new(&[("key_1", "value_1")]);

        let labels_2 = labels.clone_with_labels(Labels::new(&[("key_2", "value_2")]));
        let label_list = labels_2.into_labels();
        assert!(label_list.contains(&Label::new("key_1", "value_1")));
        assert!(label_list.contains(&Label::new("key_2", "value_2")));

        let labels_3 =
            labels.clone_with_labels(Labels::new(&[("key_3", "value_3"), ("key_4", "value_4")]));
        let label_list = labels_3.into_labels();
        assert!(label_list.contains(&Label::new("key_1", "value_1")));
        assert!(!label_list.contains(&Label::new("key_2", "value_2")));
        assert!(label_list.contains(&Label::new("key_3", "value_3")));
        assert!(label_list.contains(&Label::new("key_4", "value_4")));
    }

    use serde_test::{assert_de_tokens_error, assert_tokens, Token};

    #[test]
    fn test_deserialization_empty() {
        assert_tokens(
            &Labels::empty(),
            &[Token::Seq { len: Some(0) }, Token::SeqEnd],
        );
    }

    #[test]
    fn test_ser_de() {
        let labels = Labels::new(&[("key_1", "value_1"), ("key_2", "value_2")]);

        assert_tokens(
            &labels,
            &[
                Token::Seq { len: Some(2) },
                Token::Seq { len: Some(2) },
                Token::String("key_1"),
                Token::String("value_1"),
                Token::SeqEnd,
                Token::Seq { len: Some(2) },
                Token::String("key_2"),
                Token::String("value_2"),
                Token::SeqEnd,
                Token::SeqEnd,
            ],
        );
    }
    #[test]
    fn test_too_many_elements_for_a_label_should_fail_de() {
        assert_de_tokens_error::<Labels>(
            &[
                Token::Seq { len: Some(1) },
                Token::Seq { len: Some(3) },
                Token::String("key_1"),
                Token::String("value_1"),
                Token::String("value_2"),
                Token::SeqEnd,
                Token::SeqEnd,
            ],
            "list `[\"key_1\", \"value_1\", \"value_2\"]` contains more than two elements, only two elements (key and value) are allowed",
        );
    }
    #[test]
    fn test_single_element_for_a_label_should_fail_de() {
        assert_de_tokens_error::<Labels>(
            &[
                Token::Seq { len: Some(1) },
                Token::Seq { len: Some(1) },
                Token::String("key_1"),
                Token::SeqEnd,
                Token::SeqEnd,
            ],
            "list `[\"key_1\"]` contains a single element, two elements (key and value) are required",
        );
    }
    #[test]
    fn test_non_string_element_for_a_label_should_fail_de() {
        assert_de_tokens_error::<Labels>(
            &[
                Token::Seq { len: Some(1) },
                Token::Seq { len: Some(2) },
                Token::String("key_1"),
                Token::I8(1),
                // assert_de_tokens_error requires no remaining token after the failure, so last two tokens should be skipped
                // Token::SeqEnd,
                // Token::SeqEnd,
            ],
            "invalid type: integer `1`, expected a string",
        );
    }
}
