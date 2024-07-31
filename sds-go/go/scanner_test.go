package sds

import (
	"bytes"
	"reflect"
	"sort"
	"testing"
)

type testResult struct {
	mutated bool
	str     string
	rules   []RuleMatch
}

type mapTestResult struct {
	event         map[string]interface{}
	rules         []RuleMatch
	expectedEvent map[string]interface{}
}

func TestCreateScannerFailOnBadRegex(t *testing.T) {
	var extraConfig ExtraConfig

	// scanner ok
	rules := []Rule{
		NewMatchingRule("rule_hello", "hello", extraConfig),
		NewMatchingRule("rule_world", "(?i)WoRlD", extraConfig),
		NewRedactingRule("rule_secret", "se..et", "aaaaaaaaa", extraConfig),
	}

	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatal("failed to create the scanner:", err.Error())
	}
	scanner.Delete()

	// this scanner creation should fail, one of the rule
	// contains a bad regex
	rules = []Rule{
		NewMatchingRule("rule_hello", "hello", extraConfig),
		NewMatchingRule("rule_world", "(?i)Wo))RlD", extraConfig),
		NewRedactingRule("rule_secret", "se..et", "aaaaaaaaa", extraConfig),
	}

	scanner, err = CreateScanner(rules)
	if err == nil {
		t.Fatal("creating the scanner should've failed")
	}
	if scanner != nil {
		t.Fatal("on failed creation, the returned scanner should be nil")
	}
}

func TestCreateScanner(t *testing.T) {
	var extraConfig ExtraConfig

	rules := []Rule{
		NewMatchingRule("rule_hello", "hello", extraConfig),
		NewMatchingRule("rule_world", "(?i)WoRlD", extraConfig),
		NewRedactingRule("rule_secret", "se..et", "aaaaaaaaa", extraConfig),
	}

	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatal("failed to create the scanner:", err.Error())
	}
	if scanner.Id == 0 {
		t.Fatal("Failed to create the scanner: id == 0")
	}

	if len(scanner.Rules) != len(rules) {
		t.Fatal("Failed to create the scanner: rules number inconsistent")
	}
}

func TestScanMapEvent(t *testing.T) {
	var extraConfig ExtraConfig

	rules := []Rule{
		NewMatchingRule("rule_hello", "hello", extraConfig),
		NewMatchingRule("rule_world", "(?i)WoRlD", extraConfig),
		NewRedactingRule("rule_secret", "se..et", "[REDACTED]", extraConfig),
	}

	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatal("failed to create the scanner:", err.Error())
	}
	defer scanner.Delete()

	testData := map[string]mapTestResult{
		"this is a one match event with mutation": {
			event: map[string]interface{}{
				"content": "this is a secret event needing redaction",
			},
			rules: []RuleMatch{{
				Path:              "content",
				RuleIdx:           2,
				ReplacementType:   ReplacementTypePlaceholder,
				StartIndex:        10,
				EndIndexExclusive: 10 + uint32(len("[REDACTED]")),
				ShiftOffset:       4,
			}},
			expectedEvent: map[string]interface{}{
				"content": "this is a [REDACTED] event needing redaction",
			},
		},
		"this is a one match event with array and mutation": {
			event: map[string]interface{}{
				"content": []interface{}{
					"this is a secret event needing redaction",
				},
			},
			rules: []RuleMatch{{
				Path:              "content[0]",
				RuleIdx:           2,
				ReplacementType:   ReplacementTypePlaceholder,
				StartIndex:        10,
				EndIndexExclusive: 10 + uint32(len("[REDACTED]")),
				ShiftOffset:       4,
			}},
			expectedEvent: map[string]interface{}{
				"content": []interface{}{
					"this is a [REDACTED] event needing redaction",
				},
			},
		},
		"this is a one match event within array of map and mutation": {
			event: map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{
						"key1": "this is a secret event needing redaction",
					},
				},
			},
			rules: []RuleMatch{{
				Path:              "content[0].key1",
				RuleIdx:           2,
				ReplacementType:   ReplacementTypePlaceholder,
				StartIndex:        10,
				EndIndexExclusive: 10 + uint32(len("[REDACTED]")),
				ShiftOffset:       4,
			}},
			expectedEvent: map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{
						"key1": "this is a [REDACTED] event needing redaction",
					},
				},
			},
		},
		// nothing 's matching
		"this is a log map to process": {
			event: map[string]interface{}{
				"message": "this is a log to process",
			},
			rules: []RuleMatch{},
		},
		// 1 match rules
		"this is a one match event": {
			event: map[string]interface{}{
				"content": "this is a hello event",
			},
			rules: []RuleMatch{{
				Path:              "content",
				RuleIdx:           0,
				ReplacementType:   ReplacementTypeNone,
				StartIndex:        10,
				EndIndexExclusive: 15,
				ShiftOffset:       0,
			}},
		},
		// 1 match rules with nesting
		"this is a one match event with nesting": {
			event: map[string]interface{}{
				"content": map[string]interface{}{
					"nested": "this is a hello event",
				},
			},
			rules: []RuleMatch{{
				Path:              "content.nested",
				RuleIdx:           0,
				StartIndex:        10,
				ReplacementType:   ReplacementTypeNone,
				EndIndexExclusive: 15,
				ShiftOffset:       0,
			}},
		},

		// 1 match rule  with array
		"this is a one match event with array": {
			event: map[string]interface{}{
				"content": []interface{}{
					"this is a hello event",
				},
			},
			rules: []RuleMatch{{
				Path:              "content[0]",
				RuleIdx:           0,
				ReplacementType:   ReplacementTypeNone,
				StartIndex:        10,
				EndIndexExclusive: 15,
				ShiftOffset:       0,
			}},
		},

		// 2 match rule with map nested in array
		"this is a two match event with array": {
			event: map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{
						"nested0": "this is a hello event",
					},
					map[string]interface{}{
						"nested1": "this is a hello event",
					},
				},
			},
			rules: []RuleMatch{{
				Path:              "content[0].nested0",
				RuleIdx:           0,
				ReplacementType:   ReplacementTypeNone,
				StartIndex:        10,
				EndIndexExclusive: 15,
				ShiftOffset:       0,
			}, {
				Path:              "content[1].nested1",
				RuleIdx:           0,
				ReplacementType:   ReplacementTypeNone,
				StartIndex:        10,
				EndIndexExclusive: 15,
				ShiftOffset:       0,
			}},
		},
	}
	runTestMap(t, scanner, testData)
}

func TestScanStringWithHash(t *testing.T) {
	var extraConfig ExtraConfig

	rules := []Rule{
		NewHashRule("rule_secret", "se..et", extraConfig),
	}

	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatal("failed to create the scanner:", err.Error())
	}
	defer scanner.Delete()
	event := "this is a hello event, and containing a secret here!"
	result, err := scanner.Scan([]byte(event))
	if err != nil {
		t.Fatal("failed to scan the event:", err.Error())
	}
	if !result.Mutated {
		t.Fatal("Failed to scan the event: not mutated")
	}
	if len(result.scanResult.Matches) != 1 {
		t.Fatal("Failed to scan the event: not the good amount of rules returned")
	}
	if result.scanResult.Matches[0].ReplacementType != ReplacementTypeHash {
		t.Fatal("Failed to scan the event: not hashed")
	}

}

func TestScanStringEvent(t *testing.T) {
	var extraConfig ExtraConfig

	rules := []Rule{
		NewMatchingRule("rule_hello", "hello", extraConfig),
		NewMatchingRule("rule_world", "(?i)WoRlD", extraConfig),
		NewRedactingRule("rule_secret", "se..et", "[REDACTED]", extraConfig),
	}

	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatal("failed to create the scanner:", err.Error())
	}
	defer scanner.Delete()

	testData := map[string]testResult{
		// nothing 's matching
		"this is a log to process": {
			mutated: false,
			str:     "this is a log to process",
			rules:   []RuleMatch{},
		},
		// 1 match rules
		"this is a hello event": {
			mutated: false,
			str:     "this is a hello event",
			rules: []RuleMatch{{
				RuleIdx:           0,
				ReplacementType:   ReplacementTypeNone,
				StartIndex:        10,
				EndIndexExclusive: 15,
				ShiftOffset:       0,
			}},
		},
		// 2 match rules matching 3 times (2 times first 1 time second)
		"this is a hello event, even a hello world!": {
			mutated: false,
			str:     "this is a hello event, even a hello world!",
			rules: []RuleMatch{{
				RuleIdx:           0,
				ReplacementType:   ReplacementTypeNone,
				StartIndex:        10,
				EndIndexExclusive: 15,
				ShiftOffset:       0,
			}, {
				RuleIdx:           0,
				ReplacementType:   ReplacementTypeNone,
				StartIndex:        30,
				EndIndexExclusive: 35,
				ShiftOffset:       0,
			}, {
				RuleIdx:           1,
				ReplacementType:   ReplacementTypeNone,
				StartIndex:        36,
				EndIndexExclusive: 41,
				ShiftOffset:       0,
			}},
		},
		// one match and one redacting rule
		"this is a hello event, and containing a secret here!": {
			mutated: true,
			str:     "this is a hello event, and containing a [REDACTED] here!",
			rules: []RuleMatch{{
				RuleIdx:           0,
				ReplacementType:   ReplacementTypeNone,
				StartIndex:        10,
				EndIndexExclusive: 10 + uint32(len("hello")),
				ShiftOffset:       0,
			}, {
				RuleIdx:           2,
				ReplacementType:   ReplacementTypePlaceholder,
				StartIndex:        40,
				EndIndexExclusive: 40 + uint32(len("[REDACTED]")),
				ShiftOffset:       4,
			}},
		},
	}

	runTest(t, scanner, testData)
}

func TestScanStringEventMultipleMutations(t *testing.T) {
	var extraConfig ExtraConfig

	rules := []Rule{
		NewMatchingRule("rule_hello", "hello", extraConfig),
		NewRedactingRule("rule_secret", "se..et", "[REDACTED]", extraConfig),
		NewRedactingRule("rule_numbers", "[0-9]{4}", "[NREDAC]", extraConfig),
	}

	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatal("failed to create the scanner:", err.Error())
	}
	defer scanner.Delete()

	testData := map[string]testResult{
		"this is a log to process": {
			mutated: false,
			str:     "this is a log to process",
			rules:   []RuleMatch{},
		},
		"here there are two matches resulting to some redacting, here the secret word and here some 1234 random numbers": {
			mutated: true,
			str:     "here there are two matches resulting to some redacting, here the [REDACTED] word and here some [NREDAC] random numbers",
			rules: []RuleMatch{{
				RuleIdx:           1,
				StartIndex:        65,
				ReplacementType:   ReplacementTypePlaceholder,
				EndIndexExclusive: 65 + uint32(len("[REDACTED]")),
				ShiftOffset:       4,
			}, {
				RuleIdx:           2,
				StartIndex:        95,
				ReplacementType:   ReplacementTypePlaceholder,
				EndIndexExclusive: 95 + uint32(len("[NREDAC]")),
				ShiftOffset:       8,
			}},
		},
	}

	runTest(t, scanner, testData)
}

func TestProximityKeywords(t *testing.T) {
	extraConfig := ExtraConfig{
		ProximityKeywords: CreateProximityKeywordsConfig(10, []string{"card"}, nil),
	}

	rules := []Rule{
		NewMatchingRule("rule_6_numbers", "[0-9]{6}", extraConfig),
	}

	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatal("failed to create the scanner:", err.Error())
	}
	defer scanner.Delete()

	testData := map[string]testResult{
		"this is a log to process, no match no partial redact nor anything": {
			mutated: false,
			str:     "this is a log to process, no match no partial redact nor anything",
			rules:   []RuleMatch{},
		},
		"here card 237339, this one should match, but this second one 382448 should not as it's not prefixed by card": {
			mutated: false,
			str:     "here card 237339, this one should match, but this second one 382448 should not as it's not prefixed by card",
			rules: []RuleMatch{{
				RuleIdx:           0,
				StartIndex:        10,
				ReplacementType:   ReplacementTypeNone,
				EndIndexExclusive: 16,
				ShiftOffset:       0,
			},
			}},
	}

	runTest(t, scanner, testData)
}

func TestSecondaryValidator(t *testing.T) {
	scannerWithoutChecksum, err := CreateScanner([]Rule{
		NewRedactingRule("rule_card",
			"\\b4\\d{3}(?:(?:\\s\\d{4}){3}|(?:\\.\\d{4}){3}|(?:-\\d{4}){3}|(?:\\d{9}(?:\\d{3}(?:\\d{3})?)?))\\b",
			"[redacted]", ExtraConfig{}),
	})
	if err != nil {
		t.Fatal("failed to create the scanner wo checksum:", err.Error())
	}
	defer scannerWithoutChecksum.Delete()
	scannerWithChecksum, err := CreateScanner([]Rule{
		NewRedactingRule("rule_card",
			"\\b4\\d{3}(?:(?:\\s\\d{4}){3}|(?:\\.\\d{4}){3}|(?:-\\d{4}){3}|(?:\\d{9}(?:\\d{3}(?:\\d{3})?)?))\\b",
			"[redacted]", ExtraConfig{SecondaryValidator: LuhnChecksum}),
	})
	if err != nil {
		t.Fatal("failed to create the scanner with checksum:", err.Error())
	}
	defer scannerWithChecksum.Delete()

	testData := map[string]testResult{
		"4556997807150071 4111 1111 1111 1111": {
			mutated: true,
			str:     "[redacted] [redacted]",
			rules: []RuleMatch{
				{
					RuleIdx:           0,
					StartIndex:        0,
					ReplacementType:   ReplacementTypePlaceholder,
					EndIndexExclusive: 10,
					ShiftOffset:       -6,
				}, {
					RuleIdx:           0,
					StartIndex:        11,
					ReplacementType:   ReplacementTypePlaceholder,
					EndIndexExclusive: 21,
					ShiftOffset:       -15,
				},
			},
		},
	}
	runTest(t, scannerWithoutChecksum, testData)

	testData = map[string]testResult{
		"4556997807150071 4111 1111 1111 1111": {
			mutated: true,
			str:     "4556997807150071 [redacted]",
			rules: []RuleMatch{{
				RuleIdx:           0,
				StartIndex:        17,
				ReplacementType:   ReplacementTypePlaceholder,
				EndIndexExclusive: 27,
				ShiftOffset:       -9,
			}},
		},
	}
	runTest(t, scannerWithChecksum, testData)
}

func TestPartialRedactStart(t *testing.T) {
	extraConfig := ExtraConfig{
		ProximityKeywords: CreateProximityKeywordsConfig(10, []string{"card"}, nil),
	}

	rules := []Rule{
		NewPartialRedactRule("rule_6_numbers", "[0-9]{6}", 4, FirstCharacters, extraConfig),
	}
	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatal("failed to create the scanner:", err.Error())
	}
	defer scanner.Delete()

	testData := map[string]testResult{
		"this is a log to process, no match no partial redact nor anything": {
			mutated: false,
			str:     "this is a log to process, no match no partial redact nor anything",
			rules:   []RuleMatch{},
		},
		"here card 328339, this one should match, but this second one 382448 should not as it's not prefixed by card": {
			mutated: true,
			str:     "here card ****39, this one should match, but this second one 382448 should not as it's not prefixed by card",
			rules: []RuleMatch{{
				RuleIdx:           0,
				ReplacementType:   ReplacementTypePartialStart,
				StartIndex:        10,
				EndIndexExclusive: 16,
				ShiftOffset:       0,
			}},
		},
	}

	runTest(t, scanner, testData)
}

func TestPartialRedactEnd(t *testing.T) {
	extraConfig := ExtraConfig{
		ProximityKeywords: CreateProximityKeywordsConfig(10, []string{"card"}, nil),
	}

	rules := []Rule{
		NewPartialRedactRule("rule_6_numbers", "[0-9]{6}", 4, LastCharacters, extraConfig),
	}
	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatal("failed to create the scanner:", err.Error())
	}
	defer scanner.Delete()

	testData := map[string]testResult{
		"this is a log to process, no match no partial redact nor anything": {
			mutated: false,
			str:     "this is a log to process, no match no partial redact nor anything",
			rules:   []RuleMatch{},
		},
		"here card 328339, this one should match, but this second one 382448 should not as it's not prefixed by card": {
			mutated: true,
			str:     "here card 32****, this one should match, but this second one 382448 should not as it's not prefixed by card",
			rules: []RuleMatch{{
				RuleIdx:           0,
				ReplacementType:   ReplacementTypePartialEnd,
				StartIndex:        10,
				EndIndexExclusive: 16,
				ShiftOffset:       0,
			}},
		},
	}

	runTest(t, scanner, testData)
}

func TestExclude(t *testing.T) {
	rules := []Rule{
		NewRedactingRule("rule_card",
			"\\b4\\d{3}(?:(?:\\s\\d{4}){3}|(?:\\.\\d{4}){3}|(?:-\\d{4}){3}|(?:\\d{9}(?:\\d{3}(?:\\d{3})?)?))\\b",
			"[REDACTED]", ExtraConfig{
				ProximityKeywords: CreateProximityKeywordsConfig(10, nil, []string{"traceid"}),
			}),
	}

	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatal("failed to create the scanner:", err.Error())
	}
	defer scanner.Delete()

	testData := map[string]testResult{
		"this is a potato 4111 1111 1111 1111": {
			mutated: true,
			str:     "this is a potato [REDACTED]",
			rules: []RuleMatch{{
				RuleIdx:           0,
				StartIndex:        17,
				ReplacementType:   ReplacementTypePlaceholder,
				EndIndexExclusive: 17 + uint32(len("[REDACTED]")),
				ShiftOffset:       -9,
			}},
		},

		"this is a credit card 4111 1111 1111 1111": {
			mutated: true,
			str:     "this is a credit card [REDACTED]",
			rules: []RuleMatch{{
				RuleIdx:           0,
				StartIndex:        22,
				ReplacementType:   ReplacementTypePlaceholder,
				EndIndexExclusive: 22 + uint32(len("[REDACTED]")),
				ShiftOffset:       -9,
			}},
		},
		"this is a traceid 4111 1111 1111 1111": {
			mutated: false,
			str:     "this is a traceid 4111 1111 1111 1111",
			rules:   []RuleMatch{},
		},
	}

	runTest(t, scanner, testData)
}

func TestIncludeExclude(t *testing.T) {
	// Include rules take priority over exclude rules
	rules := []Rule{
		NewRedactingRule("rule_card",
			"\\b4\\d{3}(?:(?:\\s\\d{4}){3}|(?:\\.\\d{4}){3}|(?:-\\d{4}){3}|(?:\\d{9}(?:\\d{3}(?:\\d{3})?)?))\\b",
			"[REDACTED]", ExtraConfig{
				ProximityKeywords: CreateProximityKeywordsConfig(10, []string{"card"}, []string{"card", "traceid"}),
			}),
	}

	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatal("failed to create the scanner:", err.Error())
	}
	defer scanner.Delete()

	testData := map[string]testResult{
		"this is a potato 4111 1111 1111 1111": {
			mutated: false,
			str:     "this is a potato 4111 1111 1111 1111",
			rules:   []RuleMatch{},
		},

		"this is a credit card 4111 1111 1111 1111": {
			mutated: true,
			str:     "this is a credit card [REDACTED]",
			rules: []RuleMatch{{
				RuleIdx:           0,
				StartIndex:        22,
				ReplacementType:   ReplacementTypePlaceholder,
				EndIndexExclusive: 22 + uint32(len("[REDACTED]")),
				ShiftOffset:       -9,
			}},
		},
		"this is a traceid 4111 1111 1111 1111": {
			mutated: false,
			str:     "this is a traceid 4111 1111 1111 1111",
			rules:   []RuleMatch{},
		},
	}

	runTest(t, scanner, testData)
}

func runTestMap(t *testing.T, scanner *Scanner, testData map[string]mapTestResult) {
	for key, testResult := range testData {

		result, err := scanner.ScanEventsMap(testResult.event)
		if err != nil {
			t.Fatal("failed to scan the event:", err.Error())
		}

		if len(result.Matches) != len(testResult.rules) {
			t.Fatalf("Failed to scan the event: not the good amount of rules returned for event '%s', expected '%d', received '%d')", key, len(testResult.rules), len(result.Matches))
		}
		if result.Mutated {
			if !reflect.DeepEqual(testResult.expectedEvent, testResult.event) {
				t.Fatalf("Failed to scan the event: unexpected mutated event for event '%s': expected(%+v), received(%+v)", key, testResult.event, testResult.expectedEvent)
			}
		}

		sort.Slice(result.Matches, func(i, j int) bool {
			return sortRulesMatch(result.Matches[i], result.Matches[i])
		})
		sort.Slice(testResult.rules, func(i, j int) bool {
			return sortRulesMatch(testResult.rules[i], testResult.rules[i])
		})

		for i, expected := range testResult.rules {
			if expected != result.Matches[i] {
				t.Fatalf("Failed to scan the event: unexpected rule match for event '%s': expected(%+v), received(%+v)", key, expected, result.Matches[i])
			}
		}
	}
}

func runTest(t *testing.T, scanner *Scanner, testData map[string]testResult) {
	for event, expected := range testData {
		result, err := scanner.Scan([]byte(event))
		if err != nil {
			t.Fatal("failed to scan the event:", err.Error())
		}

		if !bytes.Equal([]byte(expected.str), result.Event) {
			t.Fatalf("Failed to scan the event '%s', expected '%s', received '%s')", event, expected.str, result.Event)
		}

		if len(result.Matches) != len(expected.rules) {
			t.Fatalf("Failed to scan the event: not the good amount of rules returned for event '%s', expected '%d', received '%d')", event, len(expected.rules), len(result.Matches))
		}

		if result.Mutated != expected.mutated {
			t.Fatalf("Inconsistent mutated state: expected '%v', received '%v'", expected.mutated, result.Mutated)
		}

		sort.Slice(result.Matches, func(i, j int) bool {
			return sortRulesMatch(result.Matches[i], result.Matches[i])
		})
		sort.Slice(expected.rules, func(i, j int) bool {
			return sortRulesMatch(expected.rules[i], expected.rules[i])
		})

		for i, expected := range expected.rules {
			if expected != result.Matches[i] {
				t.Fatalf("Failed to scan the event: unexpected rule match for event '%s': expected(%+v), received(%+v)", event, expected, result.Matches[i])
			}
		}
	}
}

func sortRulesMatch(left, right RuleMatch) bool {
	if left.RuleIdx > right.RuleIdx {
		return true
	}
	if left.StartIndex > right.StartIndex {
		return true
	}
	if left.EndIndexExclusive > right.EndIndexExclusive {
		return true
	}
	if left.Path > right.Path {
		return true
	}
	// TODO(https://datadoghq.atlassian.net/browse/SDS-301): implement replacement type
	return false
}
