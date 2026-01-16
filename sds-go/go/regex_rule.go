package dd_sds

/*
#include <stdlib.h>
#include <dd_sds.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

type RegexRuleConfig struct {
	Id                      string                   `json:"id"`
	Pattern                 string                   `json:"pattern"`
	MatchAction             MatchAction              `json:"match_action"`
	ProximityKeywords       *ProximityKeywordsConfig `json:"proximity_keywords,omitempty"`
	SecondaryValidator      *SecondaryValidator      `json:"validator,omitempty"`
	ThirdPartyActiveChecker ThirdPartyActiveChecker  `json:"third_party_active_checker,omitempty"`
	PatternCaptureGroups    []string                 `json:"pattern_capture_groups,omitempty"`
}

// ThirdPartyActiveChecker is used to validate if a given match is still active or not. It applies well to tokens that have an expiration date for instance.
type ThirdPartyActiveChecker struct {
	Type   string                        `json:"type"`
	Config ThirdPartyActiveCheckerConfig `json:"config"`
}

type ThirdPartyActiveCheckerConfig struct {
	*ThirdPartyActiveCheckerConfigAws
	*ThirdPartyActiveCheckerConfigHttp
}

type Duration struct {
	Seconds uint64 `json:"secs"`
	Nanos   uint64 `json:"nanos"`
}

type ThirdPartyActiveCheckerConfigAws struct {
	Kind           string   `json:"kind"`
	AwsStsEndpoint string   `json:"aws_sts_endpoint"`
	Timeout        Duration `json:"timeout"`
}

type StatusCodeRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type ThirdPartyActiveCheckerConfigHttp struct {
	Endpoint               string            `json:"endpoint"`
	Hosts                  []string          `json:"hosts,omitempty"`
	Method                 string            `json:"http_method"`
	RequestHeader          map[string]string `json:"request_headers"`
	ValidHttpStatusCodes   []StatusCodeRange `json:"valid_http_status_code"`
	InvalidHttpStatusCodes []StatusCodeRange `json:"invalid_http_status_code"`
	Timeout                int               `json:"timeout_seconds"`
}

// MarshalJSON implements custom JSON marshaling to handle empty validation types
func (t ThirdPartyActiveChecker) MarshalJSON() ([]byte, error) {
	// If Type is empty, marshal as null to omit the field
	if t.Type == "" {
		return []byte("null"), nil
	}

	// Otherwise, marshal normally
	type Alias ThirdPartyActiveChecker
	return json.Marshal((Alias)(t))
}

type MatchActionType string
type ReplacementType string

const (
	MatchActionNone          = MatchActionType("None")
	MatchActionRedact        = MatchActionType("Redact")
	MatchActionHash          = MatchActionType("Hash")
	MatchActionPartialRedact = MatchActionType("PartialRedact")

	ReplacementTypeNone         = ReplacementType("none")
	ReplacementTypePlaceholder  = ReplacementType("placeholder")
	ReplacementTypeHash         = ReplacementType("hash")
	ReplacementTypePartialStart = ReplacementType("partial_beginning")
	ReplacementTypePartialEnd   = ReplacementType("partial_end")
)

type SecondaryValidatorType string

const (
	LuhnChecksum      = SecondaryValidatorType("LuhnChecksum")
	ChineseIdChecksum = SecondaryValidatorType("ChineseIdChecksum")
	JwtValidatorType  = SecondaryValidatorType("JwtClaimsValidator")
)

// SecondaryValidator represents a secondary validator that can optionally have configuration
type SecondaryValidator struct {
	Type   SecondaryValidatorType `json:"type"`
	Config interface{}            `json:"config,omitempty"`
}

// NewSecondaryValidator creates a simple validator without configuration
func NewSecondaryValidator(validatorType string) *SecondaryValidator {
	return &SecondaryValidator{Type: SecondaryValidatorType(validatorType)}
}

// NewJwtClaimsValidator creates a JWT claims checker validator with configuration
func NewJwtClaimsValidator(config JwtClaimsValidatorConfig) *SecondaryValidator {
	return &SecondaryValidator{
		Type:   JwtValidatorType,
		Config: config,
	}
}

type PartialRedactionDirection string

const (
	FirstCharacters = PartialRedactionDirection("FirstCharacters")
	LastCharacters  = PartialRedactionDirection("LastCharacters")
)

// ExtraConfig is used to provide more configuration while creating the rules.
type ExtraConfig struct {
	ProximityKeywords       *ProximityKeywordsConfig
	SecondaryValidator      *SecondaryValidator
	ThirdPartyActiveChecker ThirdPartyActiveChecker
	PatternCaptureGroups    []string
}

// CreateProximityKeywordsConfig creates a ProximityKeywordsConfig.
func CreateProximityKeywordsConfig(lookAheadCharaceterCount uint32, includedKeywords []string, excludedKeywords []string) *ProximityKeywordsConfig {
	if includedKeywords == nil {
		includedKeywords = []string{}
	}
	if excludedKeywords == nil {
		excludedKeywords = []string{}
	}
	return &ProximityKeywordsConfig{
		LookAheadCharacterCount: lookAheadCharaceterCount,
		IncludedKeywords:        includedKeywords,
		ExcludedKeywords:        excludedKeywords,
	}
}

// ProximityKeywordsConfig represents the proximity keyword matching
// for the core library.
type ProximityKeywordsConfig struct {
	LookAheadCharacterCount uint32   `json:"look_ahead_character_count"`
	IncludedKeywords        []string `json:"included_keywords"`
	ExcludedKeywords        []string `json:"excluded_keywords"`
}

type MatchStatus string

const (
	// The ordering here is important, values further down the list have a higher priority when merging.
	MatchStatusNotChecked   = MatchStatus("NotChecked")
	MatchStatusNotAvailable = MatchStatus("NotAvailable")
	MatchStatusInvalid      = MatchStatus("Invalid")
	MatchStatusError        = MatchStatus("Error")
	MatchStatusValid        = MatchStatus("Valid")
)

// RuleMatch stores the matches reported by the core library.
type RuleMatch struct {
	RuleIdx           uint32
	Path              string
	ReplacementType   ReplacementType
	StartIndex        uint32
	EndIndexExclusive uint32
	ShiftOffset       int32
	MatchStatus       MatchStatus
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
func NewMatchingRule(id string, pattern string, extraConfig ExtraConfig) RegexRuleConfig {
	return RegexRuleConfig{
		Id:      id,
		Pattern: pattern,
		MatchAction: MatchAction{
			Type: MatchActionNone,
		},
		ProximityKeywords:       extraConfig.ProximityKeywords,
		SecondaryValidator:      extraConfig.SecondaryValidator,
		ThirdPartyActiveChecker: extraConfig.ThirdPartyActiveChecker,
		PatternCaptureGroups:    extraConfig.PatternCaptureGroups,
	}
}

func (c RegexRuleConfig) CreateRule() (*Rule, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	cdata := C.CString(string(data)) // this call adds the 0, memory has to be freed
	defer C.free(unsafe.Pointer(cdata))

	ptr := C.create_regex_rule(cdata)
	if ptr < 0 {
		return nil, fmt.Errorf("Failed to create regex rule with id %s", c.Id)
	} else {
		return &Rule{nativeRulePtr: int64(ptr)}, nil
	}
}

// NewRedactingRule returns a matching rule redacting events.
func NewRedactingRule(id string, pattern string, redactionValue string, extraConfig ExtraConfig) RegexRuleConfig {
	return RegexRuleConfig{
		Id:      id,
		Pattern: pattern,
		MatchAction: MatchAction{
			Type:           MatchActionRedact,
			RedactionValue: redactionValue,
		},
		ProximityKeywords:       extraConfig.ProximityKeywords,
		SecondaryValidator:      extraConfig.SecondaryValidator,
		ThirdPartyActiveChecker: extraConfig.ThirdPartyActiveChecker,
		PatternCaptureGroups:    extraConfig.PatternCaptureGroups,
	}
}

// NewHashRule returns a matching rule redacting with hashes.
func NewHashRule(id string, pattern string, extraConfig ExtraConfig) RegexRuleConfig {
	return RegexRuleConfig{
		Id:      id,
		Pattern: pattern,
		MatchAction: MatchAction{
			Type: MatchActionHash,
		},
		ProximityKeywords:       extraConfig.ProximityKeywords,
		SecondaryValidator:      extraConfig.SecondaryValidator,
		ThirdPartyActiveChecker: extraConfig.ThirdPartyActiveChecker,
		PatternCaptureGroups:    extraConfig.PatternCaptureGroups,
	}
}

// NewPartialRedactRule returns a matching rule partially redacting matches.
func NewPartialRedactRule(id string, pattern string, characterCount uint32, direction PartialRedactionDirection, extraConfig ExtraConfig) RegexRuleConfig {
	return RegexRuleConfig{
		Id:      id,
		Pattern: pattern,
		MatchAction: MatchAction{
			Type:           MatchActionPartialRedact,
			CharacterCount: characterCount,
			Direction:      direction,
		},
		ProximityKeywords:       extraConfig.ProximityKeywords,
		SecondaryValidator:      extraConfig.SecondaryValidator,
		ThirdPartyActiveChecker: extraConfig.ThirdPartyActiveChecker,
	}
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
