package dd_sds

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// JwtClaimsValidatorConfig represents the configuration for JWT claims validation
type JwtClaimsValidatorConfig struct {
	RequiredClaims  map[string]ClaimRequirement `json:"required_claims"`
	RequiredHeaders map[string]ClaimRequirement `json:"required_headers"`
}

// UnmarshalJSON handles custom deserialization of JwtClaimsValidatorConfig
func (j *JwtClaimsValidatorConfig) UnmarshalJSON(data []byte) error {
	var rawConfig struct {
		RequiredClaims  map[string]json.RawMessage `json:"required_claims"`
		RequiredHeaders map[string]json.RawMessage `json:"required_headers"`
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rawConfig); err != nil {
		return err
	}

	j.RequiredClaims = make(map[string]ClaimRequirement)
	for claimName, rawRequirement := range rawConfig.RequiredClaims {
		requirement, err := UnmarshalClaimRequirement(rawRequirement)
		if err != nil {
			return fmt.Errorf("failed to unmarshal claim requirement for '%s': %v", claimName, err)
		}
		j.RequiredClaims[claimName] = requirement
	}

	j.RequiredHeaders = make(map[string]ClaimRequirement)
	for headerName, rawRequirement := range rawConfig.RequiredHeaders {
		requirement, err := UnmarshalClaimRequirement(rawRequirement)
		if err != nil {
			return fmt.Errorf("failed to unmarshal header requirement for '%s': %v", headerName, err)
		}
		j.RequiredHeaders[headerName] = requirement
	}

	return nil
}

// ClaimRequirement represents a requirement for a JWT claim
type ClaimRequirement interface {
	claimRequirementType() string
}

// ClaimRequirementPresent represents a claim that must be present (not null)
type ClaimRequirementPresent struct{}

func (c ClaimRequirementPresent) claimRequirementType() string { return "Present" }

func (c ClaimRequirementPresent) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type": "Present",
	})
}

// ClaimRequirementExactValue represents a claim that must have an exact string value
type ClaimRequirementExactValue struct {
	Value string
}

func (c ClaimRequirementExactValue) claimRequirementType() string { return "ExactValue" }

func (c ClaimRequirementExactValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":   "ExactValue",
		"config": c.Value,
	})
}

// ClaimRequirementRegexMatch represents a claim that must match a regex pattern
type ClaimRequirementRegexMatch struct {
	Pattern string
}

func (c ClaimRequirementRegexMatch) claimRequirementType() string { return "RegexMatch" }

func (c ClaimRequirementRegexMatch) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":   "RegexMatch",
		"config": c.Pattern,
	})
}

// UnmarshalClaimRequirement handles deserialization of ClaimRequirement from the tagged union format
func UnmarshalClaimRequirement(data []byte) (ClaimRequirement, error) {
	// Use a local struct to ensure type property is always expected
	var rawRequirement struct {
		Type   string `json:"type"`
		Config string `json:"config"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rawRequirement); err != nil {
		return nil, fmt.Errorf("claim requirement must be a JSON object: %v", err)
	}

	switch rawRequirement.Type {
	case "Present":
		return ClaimRequirementPresent{}, nil
	case "ExactValue":
		return ClaimRequirementExactValue{Value: rawRequirement.Config}, nil
	case "RegexMatch":
		return ClaimRequirementRegexMatch{Pattern: rawRequirement.Config}, nil
	default:
		return nil, fmt.Errorf("unknown claim requirement type: %s", rawRequirement.Type)
	}
}
