package dd_sds

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestJwtClaimsValidatorConfig_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		expected JwtClaimsValidatorConfig
		wantErr  bool
	}{
		{
			name:     "empty config",
			jsonData: `{"required_claims": {}, "required_headers": {}}`,
			expected: JwtClaimsValidatorConfig{
				RequiredClaims:  map[string]ClaimRequirement{},
				RequiredHeaders: map[string]ClaimRequirement{},
			},
			wantErr: false,
		},
		{
			name: "config with claims only",
			jsonData: `{
				"required_claims": {
					"sub": {"type": "Present"},
					"aud": {"type": "ExactValue", "config": "my-audience"}
				},
				"required_headers": {}
			}`,
			expected: JwtClaimsValidatorConfig{
				RequiredClaims: map[string]ClaimRequirement{
					"sub": ClaimRequirementPresent{},
					"aud": ClaimRequirementExactValue{Value: "my-audience"},
				},
				RequiredHeaders: map[string]ClaimRequirement{},
			},
			wantErr: false,
		},
		{
			name: "config with headers only",
			jsonData: `{
				"required_claims": {},
				"required_headers": {
					"kid": {"type": "ExactValue", "config": "key-123"},
					"alg": {"type": "RegexMatch", "config": "^HS\\d+$"}
				}
			}`,
			expected: JwtClaimsValidatorConfig{
				RequiredClaims: map[string]ClaimRequirement{},
				RequiredHeaders: map[string]ClaimRequirement{
					"kid": ClaimRequirementExactValue{Value: "key-123"},
					"alg": ClaimRequirementRegexMatch{Pattern: "^HS\\d+$"},
				},
			},
			wantErr: false,
		},
		{
			name: "config with both claims and headers",
			jsonData: `{
				"required_claims": {
					"sub": {"type": "Present"},
					"iss": {"type": "ExactValue", "config": "my-issuer"}
				},
				"required_headers": {
					"kid": {"type": "ExactValue", "config": "key-456"},
					"typ": {"type": "RegexMatch", "config": "^JWT$"}
				}
			}`,
			expected: JwtClaimsValidatorConfig{
				RequiredClaims: map[string]ClaimRequirement{
					"sub": ClaimRequirementPresent{},
					"iss": ClaimRequirementExactValue{Value: "my-issuer"},
				},
				RequiredHeaders: map[string]ClaimRequirement{
					"kid": ClaimRequirementExactValue{Value: "key-456"},
					"typ": ClaimRequirementRegexMatch{Pattern: "^JWT$"},
				},
			},
			wantErr: false,
		},
		{
			name: "backwards compatibility - missing required_headers field",
			jsonData: `{
				"required_claims": {
					"sub": {"type": "Present"}
				}
			}`,
			expected: JwtClaimsValidatorConfig{
				RequiredClaims: map[string]ClaimRequirement{
					"sub": ClaimRequirementPresent{},
				},
				RequiredHeaders: map[string]ClaimRequirement{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var config JwtClaimsValidatorConfig
			err := json.Unmarshal([]byte(tt.jsonData), &config)

			if (err != nil) != tt.wantErr {
				t.Errorf("JwtClaimsValidatorConfig.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			// Check required claims
			if len(config.RequiredClaims) != len(tt.expected.RequiredClaims) {
				t.Errorf("RequiredClaims length = %v, want %v", len(config.RequiredClaims), len(tt.expected.RequiredClaims))
			}

			for key, expectedReq := range tt.expected.RequiredClaims {
				actualReq, exists := config.RequiredClaims[key]
				if !exists {
					t.Errorf("Missing required claim: %v", key)
					continue
				}
				if actualReq.claimRequirementType() != expectedReq.claimRequirementType() {
					t.Errorf("RequiredClaims[%v] type = %v, want %v", key, actualReq.claimRequirementType(), expectedReq.claimRequirementType())
				}
			}

			// Check required headers
			if len(config.RequiredHeaders) != len(tt.expected.RequiredHeaders) {
				t.Errorf("RequiredHeaders length = %v, want %v", len(config.RequiredHeaders), len(tt.expected.RequiredHeaders))
			}

			for key, expectedReq := range tt.expected.RequiredHeaders {
				actualReq, exists := config.RequiredHeaders[key]
				if !exists {
					t.Errorf("Missing required header: %v", key)
					continue
				}
				if actualReq.claimRequirementType() != expectedReq.claimRequirementType() {
					t.Errorf("RequiredHeaders[%v] type = %v, want %v", key, actualReq.claimRequirementType(), expectedReq.claimRequirementType())
				}
			}
		})
	}
}

func TestJwtClaimsValidatorConfig_MarshalJSON(t *testing.T) {
	config := JwtClaimsValidatorConfig{
		RequiredClaims: map[string]ClaimRequirement{
			"sub": ClaimRequirementPresent{},
			"iss": ClaimRequirementExactValue{Value: "my-issuer"},
		},
		RequiredHeaders: map[string]ClaimRequirement{
			"kid": ClaimRequirementExactValue{Value: "key-123"},
			"alg": ClaimRequirementRegexMatch{Pattern: "^HS\\d+$"},
		},
	}

	jsonData, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	// Unmarshal to verify round-trip
	var unmarshaledConfig JwtClaimsValidatorConfig
	err = json.Unmarshal(jsonData, &unmarshaledConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify the round-trip preserved the data
	if len(unmarshaledConfig.RequiredClaims) != len(config.RequiredClaims) {
		t.Errorf("RequiredClaims length after round-trip = %v, want %v", len(unmarshaledConfig.RequiredClaims), len(config.RequiredClaims))
	}

	if len(unmarshaledConfig.RequiredHeaders) != len(config.RequiredHeaders) {
		t.Errorf("RequiredHeaders length after round-trip = %v, want %v", len(unmarshaledConfig.RequiredHeaders), len(config.RequiredHeaders))
	}
}

func TestJwtClaimsValidatorConfig_UnmarshalJSON_with_unknown_field(t *testing.T) {
	valid := `{"required_claims": {"sub":{"type":"Present"}}, "required_headers": {}}`
	withUnknown := `{"required_claims": {"sub":{"type":"Present"}}, "required_headers": {}, "unknown_field":"unknown_value"}`

	tests := []struct {
		name          string
		jsonInput     string
		expectedError error
	}{
		{
			name:          "unmarshal valid config",
			jsonInput:     valid,
			expectedError: nil,
		},
		{
			name:          "unmarshal with unknown field",
			jsonInput:     withUnknown,
			expectedError: errors.New("json: unknown field \"unknown_field\""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg JwtClaimsValidatorConfig
			err := json.Unmarshal([]byte(tt.jsonInput), &cfg)
			if tt.expectedError == nil {
				if err != nil {
					t.Fatalf("Expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Expected error: %v, got: nil", tt.expectedError)
			}
			if err.Error() != tt.expectedError.Error() {
				t.Fatalf("Expected error: %q, got: %q", tt.expectedError.Error(), err.Error())
			}
		})
	}
}
