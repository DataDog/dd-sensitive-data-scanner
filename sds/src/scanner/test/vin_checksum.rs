use crate::{MatchAction, RegexRuleConfig, RootRuleConfig, Scanner, SecondaryValidator};

fn validator() -> SecondaryValidator {
    serde_json::from_str(r#"{"type":"VinChecksum"}"#).expect("VIN checksum must be supported")
}

#[test]
fn vin_checksum_accepts_independent_vectors_and_ascii_case() {
    let validator = validator().compile();
    // GB 16735-2019 Appendix A (zero) and published VIN examples (numeric/X).
    for vin in [
        "LFWADRJF011002346",
        "5YJ3E1EAXHF000316",
        "1HGBH41JXMN109186",
        "LZPTCAP2561500278",
        "LJSKA3BF3CD820005",
        "5yj3e1eaxhf000316",
        "lFwAdRjF011002346",
    ] {
        assert!(validator.is_valid_match(vin), "rejected {vin}");
    }
}

#[test]
fn vin_checksum_rejects_historical_invalid_examples_and_malformed_input() {
    let validator = validator().compile();
    for vin in [
        "L5BGA2V58NG590409",
        "3D7KA28693G723011",
        "2FMDK36C18BA04895",
        "5YJ3E1EA0HF000316",
        "5YJ3E1EAXHF000317",
        "LFWADRJFA11002346",
        "",
        "LFWADRJF01100234",
        "LFWADRJF0110023460",
        "LFWADRJF 11002346",
        "LFWADRJF-11002346",
        "LFWADRJF_11002346",
        "LFWADRJF/11002346",
        "LFWADRJF01100234é",
        "LFWADRJF0110023é",
        "ＬFWADRJF011002346",
    ] {
        assert!(!validator.is_valid_match(vin), "accepted {vin}");
    }
    for forbidden in [b'I', b'O', b'Q', b'i', b'o', b'q'] {
        for position in 0..17 {
            let mut vin = b"LFWADRJF011002346".to_vec();
            vin[position] = forbidden;
            let vin = String::from_utf8(vin).unwrap();
            assert!(!validator.is_valid_match(&vin), "accepted {vin}");
        }
    }
}

#[test]
fn vin_checksum_accepts_only_the_expected_ninth_character() {
    let validator = validator().compile();
    for vin in ["LFWADRJF011002346", "5YJ3E1EAXHF000316"] {
        for character in b"0123456789ABCDEFGHJKLMNPRSTUVWXYZ" {
            let mut candidate = vin.as_bytes().to_vec();
            candidate[8] = *character;
            let candidate = String::from_utf8(candidate).unwrap();
            assert_eq!(
                validator.is_valid_match(&candidate),
                candidate == vin,
                "{candidate}"
            );
        }
    }
}

#[test]
fn vin_checksum_transliterates_every_allowed_character() {
    let validator = validator().compile();
    // With only position one nonzero, its weight of eight determines the check digit.
    for (characters, check_digit) in [
        ("0", b'0'),
        ("1AJ", b'8'),
        ("2BKS", b'5'),
        ("3CLT", b'2'),
        ("4DMU", b'X'),
        ("5ENV", b'7'),
        ("6FW", b'4'),
        ("7GPX", b'1'),
        ("8HY", b'9'),
        ("9RZ", b'6'),
    ] {
        for character in characters.bytes() {
            let mut vin = *b"00000000000000000";
            vin[0] = character;
            vin[8] = check_digit;
            let vin = std::str::from_utf8(&vin).unwrap();
            assert!(validator.is_valid_match(vin), "rejected {vin}");
        }
    }
}

#[test]
fn vin_checksum_round_trips_configuration() {
    assert_eq!(
        serde_json::to_string(&validator()).unwrap(),
        r#"{"type":"VinChecksum"}"#
    );
}

#[test]
fn vin_checksum_checks_integrity_not_vehicle_issuance() {
    let validator = validator().compile();
    for vin in ["00000000000000000", "11111111111111111"] {
        assert!(validator.is_valid_match(vin));
    }
}

#[test]
fn vin_checksum_filters_candidates_and_continues_scanning() {
    let config: RegexRuleConfig =
        serde_json::from_str(r#"{"pattern":"[A-Za-z0-9]+","validator":{"type":"VinChecksum"}}"#)
            .expect("VIN checksum configuration must deserialize");
    let scanner = Scanner::builder(&[RootRuleConfig::new(config.build()).match_action(
        MatchAction::Redact {
            replacement: "[REDACTED]".into(),
        },
    )])
    .build()
    .unwrap();
    for (input, output, matches) in [
        ("L5BGA2V58NG590409", "L5BGA2V58NG590409", 0),
        (
            "L5BGA2V58NG590409 LFWADRJF011002346",
            "L5BGA2V58NG590409 [REDACTED]",
            1,
        ),
        (
            "5YJ3E1EAXHF000316 3D7KA28693G723011",
            "[REDACTED] 3D7KA28693G723011",
            1,
        ),
    ] {
        let mut event = input.to_string();
        let result = scanner.scan(&mut event).unwrap();
        assert_eq!(event, output);
        assert_eq!(result.len(), matches);
    }
}
