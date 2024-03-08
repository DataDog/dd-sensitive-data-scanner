use metrics::{IntoLabels, Label, SharedString};

/// Holder of multiple [Label] providing some methods to easily clone and adds new labels in it.
pub struct Labels(Vec<Label>);

pub const NO_LABEL: Labels = Labels(vec![]);

impl Labels {
    pub fn clone_with_labels(
        &self,
        additional_labels: Vec<(impl Into<SharedString>, impl Into<SharedString>)>,
    ) -> Labels {
        let mut tags = self.0.clone();
        let mut additional_labels = additional_labels
            .into_iter()
            .map(|(k, v)| Label::new(k.into(), v.into()))
            .collect();
        tags.append(&mut additional_labels);
        Labels(tags)
    }

    pub fn clone_with_label(
        &self,
        additional_label: (impl Into<SharedString>, impl Into<SharedString>),
    ) -> Labels {
        let mut tags = self.0.clone();
        tags.push(Label::new(
            additional_label.0.into(),
            additional_label.1.into(),
        ));
        Labels(tags)
    }

    pub fn new(labels: Vec<(impl Into<SharedString>, impl Into<SharedString>)>) -> Self {
        Labels(
            labels
                .into_iter()
                .map(|(k, v)| Label::new(k.into(), v.into()))
                .collect(),
        )
    }
}

impl IntoLabels for Labels {
    fn into_labels(self) -> Vec<Label> {
        self.0
    }
}

#[cfg(test)]
mod test {
    use crate::observability::labels::Labels;
    use metrics::{IntoLabels, Label};

    #[test]
    fn test_clone_labels() {
        let labels = Labels::new(vec![("key_1", "value_1")]);

        let labels_2 = labels.clone_with_label(("key_2", "value_2"));
        let label_list = labels_2.into_labels();
        assert!(label_list.contains(&Label::new("key_1", "value_1")));
        assert!(label_list.contains(&Label::new("key_2", "value_2")));

        let labels_3 = labels.clone_with_labels(vec![("key_3", "value_3"), ("key_4", "value_4")]);
        let label_list = labels_3.into_labels();
        assert!(label_list.contains(&Label::new("key_1", "value_1")));
        assert!(!label_list.contains(&Label::new("key_2", "value_2")));
        assert!(label_list.contains(&Label::new("key_3", "value_3")));
        assert!(label_list.contains(&Label::new("key_4", "value_4")));
    }
}
