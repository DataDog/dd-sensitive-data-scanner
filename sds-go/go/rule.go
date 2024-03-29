package sds

import (
	"encoding/json"
)

type MatchActionType string

const (
	MatchActionNone          = MatchActionType("None")
	MatchActionRedact        = MatchActionType("Redact")
	MatchActionHash          = MatchActionType("Hash")
	MatchActionPartialRedact = MatchActionType("PartialRedact")
)

type SecondaryValidator string

const (
	LuhnChecksum      = SecondaryValidator("LuhnChecksum")
	ChineseIdChecksum = SecondaryValidator("ChineseIdChecksum")
)

type PartialRedactionDirection string

const (
	FirstCharacters = PartialRedactionDirection("FirstCharacters")
	LastCharacters  = PartialRedactionDirection("LastCharacters")
)

// Rule is sent to the core library to create scanners.
type Rule struct {
	Id                 string                   `json:"id"`
	Pattern            string                   `json:"pattern"`
	MatchAction        MatchAction              `json:"match_action"`
	ProximityKeywords  *proximityKeywordsConfig `json:"proximity_keywords,omitempty"`
	SecondaryValidator *SecondaryValidator      `json:"secondary_validator,omitempty"`
}

// ExtraConfig is used to provide more configuration while creating the rules.
type ExtraConfig struct {
	ProximityKeywords *proximityKeywordsConfig
}

// CreateProximityKeywordsConfig creates a ProximityKeywordsConfig.
func CreateProximityKeywordsConfig(lookAheadCharaceterCount uint32, includedKeywords []string, excludedKeywords []string) *proximityKeywordsConfig {
	if includedKeywords == nil {
		includedKeywords = []string{}
	}
	if excludedKeywords == nil {
		excludedKeywords = []string{}
	}
	return &proximityKeywordsConfig{
		LookAheadCharacterCount: lookAheadCharaceterCount,
		IncludedKeywords:        includedKeywords,
		ExcludedKeywords:        excludedKeywords,
	}
}

// proximityKeywordsConfig represents the proximity keyword matching
// for the core library.
type proximityKeywordsConfig struct {
	LookAheadCharacterCount uint32   `json:"look_ahead_character_count"`
	IncludedKeywords        []string `json:"included_keywords"`
	ExcludedKeywords        []string `json:"excluded_keywords"`
}

// RuleMatch stores the matches reported by the core library.
type RuleMatch struct {
	RuleIdx uint32
	// TODO(remy): not implemented yet.
	Path              string
	ReplacementType   MatchAction
	StartIndex        uint32
	EndIndexExclusive uint32
	ShiftOffset       uint32
}

// MatchAction is used to configure the rules.
type MatchAction struct {
	Type MatchActionType
	// used when Type == MatchActionRedact, empty otherwise
	RedactionValue string
	// used when Type == MatchActionPartialRedact, empty otherwise
	CharacterCount uint32
	// used when Type == MatchActionPartialRedact, empty otherwise
	Direction PartialRedactionDirection
}

// NewMatchingRule returns a matching rule with no match _action_.
func NewMatchingRule(id string, pattern string, extraConfig ExtraConfig) Rule {
	return Rule{
		Id:      id,
		Pattern: pattern,
		MatchAction: MatchAction{
			Type: MatchActionNone,
		},
		ProximityKeywords: extraConfig.ProximityKeywords,
	}
}

// NewRedactingRule returns a matching rule redacting events.
func NewRedactingRule(id string, pattern string, redactionValue string, extraConfig ExtraConfig) Rule {
	return Rule{
		Id:      id,
		Pattern: pattern,
		MatchAction: MatchAction{
			Type:           MatchActionRedact,
			RedactionValue: redactionValue,
		},
		ProximityKeywords: extraConfig.ProximityKeywords,
	}
}

// NewHashRule returns a matching rule redacting with hashes.
func NewHashRule(id string, pattern string, extraConfig ExtraConfig) Rule {
	return Rule{
		Id:      id,
		Pattern: pattern,
		MatchAction: MatchAction{
			Type: MatchActionHash,
		},
		ProximityKeywords: extraConfig.ProximityKeywords,
	}
}

// NewPartialRedactRule returns a matching rule partially redacting matches.
func NewPartialRedactRule(id string, pattern string, characterCount uint32, direction PartialRedactionDirection, extraConfig ExtraConfig) Rule {
	return Rule{
		Id:      id,
		Pattern: pattern,
		MatchAction: MatchAction{
			Type:           MatchActionPartialRedact,
			CharacterCount: characterCount,
			Direction:      direction,
		},
		ProximityKeywords: extraConfig.ProximityKeywords,
	}
}

// MarshalJSON marshales the SecondaryValidator.
func (s SecondaryValidator) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": string(s),
	})
}

// MarshalJSON marshals the MatchAction in a format understood by the serde rust
// JSON library.
func (m MatchAction) MarshalJSON() ([]byte, error) {
	o := map[string]interface{}{
		"type":         string(m.Type), // serde (rust) will use this field to know what to use for the enum
		"match_action": string(m.Type),
	}

	switch m.Type {
	case MatchActionRedact:
		o["replacement"] = m.RedactionValue
	case MatchActionPartialRedact:
		o["character_count"] = m.CharacterCount
		o["direction"] = string(m.Direction)
	}

	return json.Marshal(o)
}
