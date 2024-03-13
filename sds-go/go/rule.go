package sds

import (
	"encoding/json"
)

type MatchActionType string

const (
	MatchActionNone   = MatchActionType("None")
	MatchActionRedact = MatchActionType("Redact")
	MatchActionHash   = MatchActionType("Hash")
)

type Rule struct {
	Id          string      `json:"id"`
	Pattern     string      `json:"pattern"`
	MatchAction MatchAction `json:"match_action"`
}

type RuleMatch struct {
	RuleIdx uint32
	// TODO(remy): not implemented yet.
	Path string
	// TODO(remy): not implemented yet.
	ReplacementType   MatchAction
	StartIndex        uint32
	EndIndexExclusive uint32
	ShiftOffset       uint32
}

type MatchAction struct {
	Type MatchActionType
	// empty if MatchActionType == MatchActionNone
	RedactionValue string
}

// NewMatchingRule returns a matching rule.
func NewMatchingRule(id string, pattern string) Rule {
	return Rule{
		Id:      id,
		Pattern: pattern,
		MatchAction: MatchAction{
			Type: MatchActionNone,
		},
	}
}

// NewRedactingRule returns a matching rule redacting events.
func NewRedactingRule(id string, pattern string, redactionValue string) Rule {
	return Rule{
		Id:      id,
		Pattern: pattern,
		MatchAction: MatchAction{
			Type:           MatchActionRedact,
			RedactionValue: redactionValue,
		},
	}
}

func NewHashRule(id string, pattern string) Rule {
	return Rule{
		Id:      id,
		Pattern: pattern,
		MatchAction: MatchAction{
			Type: MatchActionHash,
		},
	}
}

// MarshalJSON marshals the MatchAction in a format understood by the serde rust
// JSON library.
func (m MatchAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type":         string(m.Type), // serde (rust) will use this field to know what to use for the enum
		"match_action": string(m.Type),
		"replacement":  m.RedactionValue,
	})
}
