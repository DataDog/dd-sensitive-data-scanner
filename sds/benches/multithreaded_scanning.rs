use criterion::Criterion;
use dd_sds::{Event, EventVisitor, Path, PathSegment, RegexRuleConfig, Utf8Encoding};
use dd_sds::Scanner;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use ahash::AHashMap;
use threadpool::ThreadPool;

pub fn multithread_scanning(c: &mut Criterion) {
    let rules: Vec<_> = sample_regexes().into_iter().map(|regex|{
        RegexRuleConfig::new(&regex).build()
    }).collect();

    let scanner = Arc::new(Scanner::builder(&rules).build().unwrap());

    let sample_inputs = sample_inputs();
    let sample_event = sample_large_event();

    let num_threads = 32;
    // There are more jobs than threads to test things that may take longer the first time
    // a thread does something (e.g. thread local storage)
    let num_jobs = 256;
    let thread_pool = ThreadPool::new(num_threads);

    c.bench_function(
        "scan single strings", |b| {
            b.iter(|| {
                for _ in 0..num_jobs {
                    let sample_inputs = sample_inputs.clone();
                    let scanner = Arc::clone(&scanner);
                    thread_pool.execute(move ||{
                        let mut sample_inputs = sample_inputs.clone();
                        let mut matches = 0;
                        for input in &mut sample_inputs {
                            let results = scanner.scan(input, vec![]);
                            matches += results.len();
                        }
                        assert_eq!(matches, 65);
                    });
                }
                thread_pool.join();
            })
        },
    );

    c.bench_function(
        "scan large event", |b| {
            b.iter(|| {
                for _ in 0..num_jobs {
                    let sample_event = sample_event.clone();
                    let scanner = Arc::clone(&scanner);
                    thread_pool.execute(move ||{
                        let mut sample_event = sample_event.clone();
                        let results = scanner.scan(&mut sample_event, vec![]);
                        assert_eq!(results.len(), 65);
                    });
                }
                thread_pool.join()
            })
        },
    );

}

// Arbitrary regexes patterns for testing.
fn sample_regexes() -> Vec<String> {
    vec![
        String::from(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), // Email address
        String::from(r"\b\d{3}-\d{2}-\d{4}\b"), // US Social Security number
        String::from(r"\b[A-CEGHJ-NPR-TW-Z]{2}\d{6}[A-D]?\b"), // UK passport number
        String::from(r"\(\d{3}\)\s?\d{3}-\d{4}|\d{3}-\d{3}-\d{4}|\d{10}"), // US phone numbers
        String::from(r"(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])/\d{4}"), // Date (MM/DD/YYYY)
        String::from(r"\b(?:\d{4}[ -]?){3}\d{4}\b"), // Credit card number
        String::from(r"\b([0-9]{9}|[A-Z]{2}[0-9]{7})\b"), // Passport number (generic)
        String::from(r"\b\d{8,17}\b"), // Various ID numbers (8-17 digits)
        String::from(r"\b[A-Z]{1,2}\d{6,8}\b"), // Vehicle registration number (various formats)
        String::from(r"\b[A-Z]{3}\d{8}\b"), // Company registration number
        String::from(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b"), // Custom alphanumeric ID
        String::from(r"\b\d{9}\b"), // Nine-digit number (e.g., SSN)
        String::from(r"(0[1-9]|1[0-2])\/\d{2}"), // Expiration date (MM/YY)
        String::from(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), // IPv4 address
        String::from(r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b"), // MAC address
        String::from(r"https?://[^\s/$.?#].[^\s]*"), // URL
        String::from(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"), // UUID
        String::from(r"\b[A-HJ-NPR-Z0-9]{17}\b"), // Vehicle Identification Number (VIN)
        String::from(r"\b\d{2}-\d{7}\b"), // National ID number (format: 2-7 digits)
        String::from(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"), // Bitcoin address
        String::from(r"\b\d{2}-\d{7}\b"), // National ID number (repeated)
        String::from(r"\b\d{6}\b"), // Six-digit number (e.g., PIN code)
        String::from(r"\b[A-Z]{3}-\d{6}\b"), // Custom alphanumeric code
        String::from(r"\b(sensitive note|confidential)\b"), // Sensitive keyword match
        String::from(r"\+\d{1,3}\s?\d{1,14}$"), // International phone number
        String::from(r"\.(docx?|xlsx?|pdf|pptx?|txt|csv)$"), // File extensions
        String::from(r"[A-Za-z0-9_-]{28}"), // API key (28 characters)
        String::from(r"\b[A-Za-z0-9]{32}\b"), // Token (32 characters)
        String::from(r"\b[a-fA-F0-9]{64}\b"), // SHA-256 hash
        String::from(r"(ftp|sftp):\/\/[^\s:@]+:[^\s@]+@([^\s\/:]+)(:[0-9]+)?\/?"), // FTP/SFTP URL
        String::from(r"\b(?:\d{4}[- ]?){3}\d{4}\b"), // Credit card number (with optional spaces or dashes)
        String::from(r"\b(sensitive|confidential|private|restricted)\b"), // Sensitive classification keywords
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BenchEvent {
    String(String),
    Map(AHashMap<String, BenchEvent>),
}

impl Event for BenchEvent {
    type Encoding = Utf8Encoding;

    fn visit_event<'path>(&'path mut self, visitor: &mut impl EventVisitor<'path>) {
        match self {
            Self::String(value) => {
                let _result = visitor.visit_string(value);
            }
            Self::Map(map) => {
                for (key, child) in map.iter_mut() {
                    visitor.push_segment(key.as_str().into());
                    child.visit_event(visitor);
                    visitor.pop_segment();
                }
            }
        }
    }

    fn visit_string_mut(&mut self, path: &Path, mut visit: impl FnMut(&mut String) -> bool) {
        let mut value = self;

        for segment in &path.segments {
            match segment {
                PathSegment::Field(key) => {
                    value = value.as_map_mut().unwrap().get_mut(key.as_ref()).unwrap();
                }
                PathSegment::Index(i) => {/* indices not supported here */}
            }
        }
        (visit)(value.as_string_mut().unwrap());
    }
}

impl BenchEvent {
    /// Gets a mutable reference to the map.
    pub fn as_map_mut(&mut self) -> Option<&mut AHashMap<String, BenchEvent>> {
        match self {
            Self::Map(x) => Some(x),
            _ => None,
        }
    }

    /// Gets a mutable reference to the map.
    pub fn as_string_mut(&mut self) -> Option<&mut String> {
        match self {
            Self::String(x) => Some(x),
            _ => None,
        }
    }
}


fn sample_inputs() -> Vec<String> {
    let mut file = File::open("data/sample_logs.txt").unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    data.lines().map(|x| x.to_string()).collect()
}

fn sample_large_event() -> BenchEvent {
    let input_strings = sample_inputs();

    let mut map = AHashMap::new();
    for (index, input) in input_strings.into_iter().enumerate() {
        map.insert(format!("{}", index), BenchEvent::String(input));
    }

    BenchEvent::Map(map)
}


criterion::criterion_group!(
    benches,
    multithread_scanning
);

criterion::criterion_main!(benches);
