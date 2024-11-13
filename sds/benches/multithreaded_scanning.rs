use ahash::AHashMap;
use criterion::Criterion;
use dd_sds::Scanner;
use dd_sds::{
    Event, EventVisitor, Path, PathSegment, ProximityKeywordsConfig, RegexRuleConfig, Utf8Encoding,
};
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use threadpool::ThreadPool;

pub fn multithread_scanning(c: &mut Criterion) {
    let rules: Vec<_> = sample_regexes()
        .into_iter()
        .map(|regex| RegexRuleConfig::new(&regex).build())
        .collect();

    let scanner = Arc::new(Scanner::builder(&rules).build().unwrap());

    let regex_with_keywords = sample_regexes_with_keywords();
    let rules_with_keywords: Vec<_> = regex_with_keywords
        .into_iter()
        .map(|(keywords, regex)| {
            RegexRuleConfig::new(&regex)
                .proximity_keywords(ProximityKeywordsConfig {
                    look_ahead_character_count: 30,
                    included_keywords: keywords,
                    excluded_keywords: vec![],
                })
                .build()
        })
        .collect();

    let scanner_with_keywords = Arc::new(Scanner::builder(&rules_with_keywords).build().unwrap());

    let sample_inputs = sample_inputs();
    let sample_event = sample_large_event();

    let num_threads = 32;
    // There are more jobs than threads to test things that may take longer the first time
    // a thread does something (e.g. thread local storage)
    let num_jobs = num_threads * 25;
    let thread_pool = ThreadPool::new(num_threads);

    c.bench_function("scan single strings (multi-threaded)", |b| {
        b.iter(|| {
            for _ in 0..num_jobs {
                let sample_inputs = sample_inputs.clone();
                let scanner = Arc::clone(&scanner);
                thread_pool.execute(move || {
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
    });

    c.bench_function("scan large event (multi-threaded)", |b| {
        b.iter(|| {
            for _ in 0..num_jobs {
                let sample_event = sample_event.clone();
                let scanner = Arc::clone(&scanner);
                thread_pool.execute(move || {
                    let mut sample_event = sample_event.clone();
                    let results = scanner.scan(&mut sample_event, vec![]);
                    assert_eq!(results.len(), 65);
                });
            }
            thread_pool.join()
        })
    });

    c.bench_function(
        "scan single strings (multi-threaded, with included keywords)",
        |b| {
            b.iter(|| {
                for _ in 0..num_jobs {
                    let sample_inputs = sample_inputs.clone();
                    let scanner = Arc::clone(&scanner_with_keywords);
                    thread_pool.execute(move || {
                        let mut sample_inputs = sample_inputs.clone();
                        let mut matches = 0;
                        for input in &mut sample_inputs {
                            let results = scanner.scan(input, vec![]);
                            matches += results.len();
                        }
                        assert_eq!(matches, 35);
                    });
                }
                thread_pool.join();
            })
        },
    );

    c.bench_function(
        "scan large event (multi-threaded, with included keywords)",
        |b| {
            b.iter(|| {
                for _ in 0..num_jobs {
                    let sample_event = sample_event.clone();
                    let scanner = Arc::clone(&scanner_with_keywords);
                    thread_pool.execute(move || {
                        let mut sample_event = sample_event.clone();
                        let results = scanner.scan(&mut sample_event, vec![]);
                        assert_eq!(results.len(), 35);
                    });
                }
                thread_pool.join()
            })
        },
    );

    c.bench_function("scan single strings (single-threaded)", |b| {
        b.iter(|| {
            for _ in 0..num_jobs {
                // The clones aren't required here, but are kept to be more comparable to the multi-threaded versions
                let sample_inputs = sample_inputs.clone();
                let scanner = Arc::clone(&scanner);
                let mut sample_inputs = sample_inputs.clone();
                let mut matches = 0;
                for input in &mut sample_inputs {
                    let results = scanner.scan(input, vec![]);
                    matches += results.len();
                }
                assert_eq!(matches, 65);
            }
        })
    });

    c.bench_function("scan large event (single-threaded)", |b| {
        b.iter(|| {
            for _ in 0..num_jobs {
                // The clones aren't required here, but are kept to be more comparable to the multi-threaded versions
                let sample_event = sample_event.clone();
                let scanner = Arc::clone(&scanner);
                let mut sample_event = sample_event.clone();
                let results = scanner.scan(&mut sample_event, vec![]);
                assert_eq!(results.len(), 65);
            }
        })
    });

    c.bench_function(
        "scan single strings (single-threaded, with included keywords)",
        |b| {
            b.iter(|| {
                for _ in 0..num_jobs {
                    // The clones aren't required here, but are kept to be more comparable to the multi-threaded versions
                    let sample_inputs = sample_inputs.clone();
                    let scanner = Arc::clone(&scanner_with_keywords);
                    let mut sample_inputs = sample_inputs.clone();
                    let mut matches = 0;
                    for input in &mut sample_inputs {
                        let results = scanner.scan(input, vec![]);
                        matches += results.len();
                    }
                    assert_eq!(matches, 35);
                }
            })
        },
    );

    c.bench_function(
        "scan large event (single-threaded, with included keywords)",
        |b| {
            b.iter(|| {
                for _ in 0..num_jobs {
                    // The clones aren't required here, but are kept to be more comparable to the multi-threaded versions
                    let sample_event = sample_event.clone();
                    let scanner = Arc::clone(&scanner_with_keywords);
                    let mut sample_event = sample_event.clone();
                    let results = scanner.scan(&mut sample_event, vec![]);
                    assert_eq!(results.len(), 35);
                }
            })
        },
    );
}

// Arbitrary regexes patterns for testing.
fn sample_regexes() -> Vec<String> {
    sample_regexes_with_keywords()
        .into_iter()
        .map(|(keywords, pattern)| pattern)
        .collect()
}

fn sample_regexes_with_keywords() -> Vec<(Vec<String>, String)> {
    vec![
        (vec!["email".to_string(), "contact".to_string(), "mail".to_string()], r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".to_string()), // Email address
        (vec!["ssn".to_string(), "social security".to_string()], r"\b\d{3}-\d{2}-\d{4}\b".to_string()), // US Social Security number
        (vec!["passport".to_string(), "uk passport".to_string()], r"\b[A-CEGHJ-NPR-TW-Z]{2}\d{6}[A-D]?\b".to_string()), // UK passport number
        (vec!["phone".to_string(), "contact".to_string()], r"\(\d{3}\)\s?\d{3}-\d{4}|\d{3}-\d{3}-\d{4}|\d{10}".to_string()), // US phone numbers
        (vec!["date".to_string(), "dob".to_string(), "birth".to_string()], r"(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])/\d{4}".to_string()), // Date (MM/DD/YYYY)
        (vec!["credit card".to_string(), "cc".to_string()], r"\b(?:\d{4}[ -]?){3}\d{4}\b".to_string()), // Credit card number
        (vec!["passport".to_string(), "id".to_string()], r"\b([0-9]{9}|[A-Z]{2}[0-9]{7})\b".to_string()), // Passport number (generic)
        (vec!["id".to_string(), "account".to_string(), "number".to_string()], r"\b\d{8,17}\b".to_string()), // Various ID numbers (8-17 digits)
        (vec!["vehicle".to_string(), "registration".to_string()], r"\b[A-Z]{1,2}\d{6,8}\b".to_string()), // Vehicle registration number
        (vec!["company".to_string(), "registration".to_string()], r"\b[A-Z]{3}\d{8}\b".to_string()), // Company registration number
        (vec!["custom id".to_string(), "identifier".to_string()], r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b".to_string()), // Custom alphanumeric ID
        (vec!["ssn".to_string(), "social security".to_string()], r"\b\d{9}\b".to_string()), // Nine-digit number (e.g., SSN)
        (vec!["expiration".to_string(), "expiry".to_string(), "date".to_string()], r"(0[1-9]|1[0-2])\/\d{2}".to_string()), // Expiration date (MM/YY)
        (vec!["ip".to_string(), "address".to_string(), "network".to_string()], r"\b(?:\d{1,3}\.){3}\d{1,3}\b".to_string()), // IPv4 address
        (vec!["mac".to_string(), "address".to_string(), "network".to_string()], r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b".to_string()), // MAC address
        (vec!["url".to_string(), "link".to_string(), "website".to_string()], r"https?://[^\s/$.?#].[^\s]*".to_string()), // URL
        (vec!["uuid".to_string(), "identifier".to_string()], r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b".to_string()), // UUID
        (vec!["vin".to_string(), "vehicle".to_string(), "identification".to_string()], r"\b[A-HJ-NPR-Z0-9]{17}\b".to_string()), // Vehicle Identification Number (VIN)
        (vec!["national id".to_string(), "id".to_string(), "identifier".to_string()], r"\b\d{2}-\d{7}\b".to_string()), // National ID number (format: 2-7 digits)
        (vec!["bitcoin".to_string(), "crypto".to_string(), "address".to_string()], r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b".to_string()), // Bitcoin address
        (vec!["pin".to_string(), "code".to_string()], r"\b\d{6}\b".to_string()), // Six-digit number (e.g., PIN code)
        (vec!["code".to_string(), "alphanumeric".to_string()], r"\b[A-Z]{3}-\d{6}\b".to_string()), // Custom alphanumeric code
        (vec!["sensitive".to_string(), "confidential".to_string(), "restricted".to_string()], r"\b(sensitive note|confidential)\b".to_string()), // Sensitive keyword match
        (vec!["phone".to_string(), "international".to_string()], r"\+\d{1,3}\s?\d{1,14}$".to_string()), // International phone number
        (vec!["file".to_string(), "extension".to_string()], r"\.(docx?|xlsx?|pdf|pptx?|txt|csv)$".to_string()), // File extensions
        (vec!["api".to_string(), "key".to_string()], r"[A-Za-z0-9_-]{28}".to_string()), // API key (28 characters)
        (vec!["token".to_string(), "auth".to_string()], r"\b[A-Za-z0-9]{32}\b".to_string()), // Token (32 characters)
        (vec!["sha-256".to_string(), "hash".to_string()], r"\b[a-fA-F0-9]{64}\b".to_string()), // SHA-256 hash
        (vec!["ftp".to_string(), "sftp".to_string(), "url".to_string()], r"(ftp|sftp):\/\/[^\s:@]+:[^\s@]+@([^\s\/:]+)(:[0-9]+)?\/?".to_string()), // FTP/SFTP URL
        (vec!["credit card".to_string(), "cc".to_string()], r"\b(?:\d{4}[- ]?){3}\d{4}\b".to_string()), // Credit card number (with optional spaces or dashes)
        (vec!["classification".to_string(), "sensitive".to_string()], r"\b(sensitive|confidential|private|restricted)\b".to_string()), // Sensitive classification keywords
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
                PathSegment::Index(i) => { /* indices not supported here */ }
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

criterion::criterion_group!(benches, multithread_scanning);

criterion::criterion_main!(benches);
