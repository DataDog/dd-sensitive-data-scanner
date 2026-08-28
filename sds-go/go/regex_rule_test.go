package dd_sds

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestMatchActionUnmarshalJSON_exportPlaceholder(t *testing.T) {
	var got MatchAction
	if err := json.Unmarshal([]byte(`{"type":"","match_action":""}`), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := MatchAction{Type: MatchActionNone}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestMatchActionUnmarshalJSON_redact(t *testing.T) {
	var got MatchAction
	raw := `{"type":"Redact","match_action":"Redact","replacement":"[REDACTED]"}`
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := MatchAction{
		Type:           MatchActionRedact,
		RedactionValue: "[REDACTED]",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestMatchActionUnmarshalJSON_partialRedact(t *testing.T) {
	var got MatchAction
	raw := `{"type":"PartialRedact","match_action":"PartialRedact","character_count":4,"direction":"FirstCharacters"}`
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := MatchAction{
		Type:           MatchActionPartialRedact,
		CharacterCount: 4,
		Direction:      FirstCharacters,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestMatchActionUnmarshalJSON_unknownField(t *testing.T) {
	err := json.Unmarshal([]byte(`{"type":"None","unexpected":true}`), &MatchAction{})
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	if !errors.Is(err, errors.New("json: unknown field \"unexpected\"")) && err.Error() != `json: unknown field "unexpected"` {
		t.Fatalf("error = %q", err)
	}
}

func TestMatchActionMarshalJSON_roundTrip(t *testing.T) {
	in := MatchAction{
		Type:           MatchActionRedact,
		RedactionValue: "[REDACTED]",
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got MatchAction
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("round trip mismatch: got %#v, want %#v", got, in)
	}
}

func TestRegexRuleConfigUnmarshalJSON_withMatchAction(t *testing.T) {
	raw := `{
		"id": "r",
		"pattern": "secret",
		"match_action": {"type":"","match_action":""}
	}`
	var cfg RegexRuleConfig
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.MatchAction.Type != MatchActionNone {
		t.Fatalf("MatchAction.Type = %q, want %q", cfg.MatchAction.Type, MatchActionNone)
	}
}

func TestRegexRuleConfigUnmarshalJSON_withPatternCaptureGroups(t *testing.T) {
	raw := `{
		"id": "r",
		"pattern": "hello (?<sds_match>world)",
		"pattern_capture_groups": ["sds_match"]
	}`
	var cfg RegexRuleConfig
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{"sds_match"}
	if !reflect.DeepEqual(cfg.PatternCaptureGroups, want) {
		t.Fatalf("PatternCaptureGroups = %#v, want %#v", cfg.PatternCaptureGroups, want)
	}
}

func TestRegexRuleConfigUnmarshalJSON_withPrecedence(t *testing.T) {
	raw := `{
		"id": "r",
		"pattern": "secret",
		"precedence": "Generic"
	}`
	var cfg RegexRuleConfig
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.Precedence != PrecedenceGeneric {
		t.Fatalf("Precedence = %q, want %q", cfg.Precedence, PrecedenceGeneric)
	}
}
