package dd_sds

import (
	"encoding/json"
	"testing"
)

func TestVinChecksumSecondaryValidator(t *testing.T) {
	validator := NewSecondaryValidator("VinChecksum")
	encoded, err := json.Marshal(validator)
	if err != nil {
		t.Fatal("failed to serialize VIN validator:", err)
	}
	if string(encoded) != `{"type":"VinChecksum"}` {
		t.Fatalf("unexpected VIN validator JSON: %s", encoded)
	}

	scanner, err := CreateScanner([]RuleConfig{
		RegexRuleConfig{
			Id:                 "vin",
			Pattern:            "[A-Za-z0-9]+",
			MatchAction:        MatchAction{Type: MatchActionRedact, RedactionValue: "[REDACTED]"},
			SecondaryValidator: validator,
		},
	})
	if err != nil {
		t.Fatal("failed to create scanner with VIN checksum through FFI:", err)
	}
	defer scanner.Delete()

	const validUS = "5YJ3E1EAXHF000316"
	const validChina = "LFWADRJF011002346"
	const invalidUS = "3D7KA28693G723011"
	const invalidChina = "L5BGA2V58NG590409"

	cases := []struct {
		name          string
		input         string
		output        string
		matchStart    uint32
		expectedMatch bool
	}{
		{name: "US X check digit", input: validUS, output: "[REDACTED]", expectedMatch: true},
		{name: "China zero check digit", input: validChina, output: "[REDACTED]", expectedMatch: true},
		{name: "lowercase VIN", input: "5yj3e1eaxhf000316", output: "[REDACTED]", expectedMatch: true},
		{name: "historical US false positive", input: invalidUS, output: invalidUS},
		{name: "historical China false positive", input: invalidChina, output: invalidChina},
		{name: "invalid letter in check position", input: "5YJ3E1EAAHF000316", output: "5YJ3E1EAAHF000316"},
		{name: "short input", input: "5YJ3E1EAXHF00031", output: "5YJ3E1EAXHF00031"},
		{
			name:          "continue from invalid to valid",
			input:         invalidChina + " " + validChina,
			output:        invalidChina + " [REDACTED]",
			matchStart:    18,
			expectedMatch: true,
		},
		{
			name:          "leave invalid after valid unchanged",
			input:         validUS + " " + invalidUS,
			output:        "[REDACTED] " + invalidUS,
			expectedMatch: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			expected := testResult{str: testCase.output, mutated: testCase.expectedMatch}
			if testCase.expectedMatch {
				expected.rules = []RuleMatch{{
					RuleIdx:           0,
					ReplacementType:   ReplacementTypePlaceholder,
					StartIndex:        testCase.matchStart,
					EndIndexExclusive: testCase.matchStart + 10,
					ShiftOffset:       -7,
				}}
			}
			runTest(t, scanner, map[string]testResult{testCase.input: expected}, false)
		})
	}
}
