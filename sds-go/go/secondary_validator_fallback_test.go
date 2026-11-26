package dd_sds

import (
	"encoding/json"
	"reflect"
	"testing"
)

func secretRuleWithValidator(id string, validator *SecondaryValidator) RegexRuleConfig {
	return RegexRuleConfig{
		Id:                 id,
		Pattern:            "secret",
		MatchAction:        MatchAction{Type: MatchActionRedact, RedactionValue: "[REDACTED]"},
		SecondaryValidator: validator,
	}
}

func createTestScanner(t *testing.T, rules ...RuleConfig) *Scanner {
	t.Helper()
	scanner, err := CreateScanner(rules)
	if err != nil {
		t.Fatalf("CreateScanner: %v", err)
	}
	t.Cleanup(scanner.Delete)
	return scanner
}

func scanString(t *testing.T, scanner *Scanner, input string) string {
	t.Helper()
	result, err := scanner.Scan([]byte(input))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return string(result.Event)
}

func TestUnknownValidatorWithPassDefaultResponseKeepsMatches(t *testing.T) {
	validator := NewSecondaryValidator("FutureValidator").WithDefaultResponse(DefaultResponsePass)
	scanner := createTestScanner(t, secretRuleWithValidator("future", validator))

	if got := scanString(t, scanner, "a secret"); got != "a [REDACTED]" {
		t.Fatalf("scan = %q", got)
	}
}

func TestSecondaryValidatorDefaultResponseRoundTrips(t *testing.T) {
	raw := `{"type":"FutureValidator","config":{"a":[1,2]},"default_response":"fail"}`
	var validator SecondaryValidator
	if err := json.Unmarshal([]byte(raw), &validator); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	encoded, err := json.Marshal(validator)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertJSONEqual(t, string(encoded), raw)
}

func assertJSONEqual(t *testing.T, got string, want string) {
	t.Helper()
	var gotValue, wantValue interface{}
	if err := json.Unmarshal([]byte(got), &gotValue); err != nil {
		t.Fatalf("invalid JSON %s: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("invalid JSON %s: %v", want, err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("JSON = %s, want %s", got, want)
	}
}
