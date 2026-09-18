package dd_sds

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func intPtr(i int) *int {
	return &i
}

func stringPtr(s string) *string {
	return &s
}

func compactJSON(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s)); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func Test_ThirdPartyActiveChecker_CustomHttpV2_RoundTrip(t *testing.T) {
	testCases := map[string]struct {
		mv             ThirdPartyActiveChecker
		expectedResult string
	}{
		"should successfully marshal a simple CustomHttpV2 validation": {
			mv: ThirdPartyActiveChecker{
				Type: ThirdPartyActiveCheckerHttpV2,
				Config: ThirdPartyActiveCheckerConfig{
					ThirdPartyActiveCheckerConfigHttpV2: &ThirdPartyActiveCheckerConfigHttpV2{
						Calls: []HttpCallConfig{
							{
								Request: HttpRequestConfig{
									Endpoint: "https://api.example.com/validate?token=$MATCH",
									Method:   "GET",
									Headers: map[string]string{
										"User-Agent": "Datadog Match Validator",
									},
								},
								Response: HttpResponseConfig{
									Conditions: []ResponseCondition{
										{
											Type:       "valid",
											StatusCode: &StatusCodeMatcher{Single: intPtr(200)},
										},
										{
											Type:       "invalid",
											StatusCode: &StatusCodeMatcher{Range: &StatusCodeRange{Start: 400, End: 500}},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedResult: `{
				"type": "CustomHttpV2",
				"config": {
					"calls": [{
						"request": {
							"endpoint": "https://api.example.com/validate?token=$MATCH",
							"method": "GET",
							"headers": {
								"User-Agent": "Datadog Match Validator"
							}
						},
						"response": {
							"conditions": [
								{"type": "valid", "status_code": 200},
								{"type": "invalid", "status_code": {"start": 400, "end": 500}}
							]
						}
					}]
				}
			}`,
		},
		"should successfully marshal CustomHttpV2 with match pairing": {
			mv: ThirdPartyActiveChecker{
				Type: ThirdPartyActiveCheckerHttpV2,
				Config: ThirdPartyActiveCheckerConfig{
					ThirdPartyActiveCheckerConfigHttpV2: &ThirdPartyActiveCheckerConfigHttpV2{
						MatchPairing: &MatchPairingConfig{
							Kind: "vendorX",
							Parameters: map[string]string{
								"client_subdomain": "$CLIENT_SUBDOMAIN",
								"client_id":        "$CLIENT_ID",
							},
						},
						Calls: []HttpCallConfig{
							{
								Request: HttpRequestConfig{
									Endpoint: "https://$CLIENT_SUBDOMAIN.vendor.com/api/v1/token/$MATCH",
									Method:   "POST",
									Headers: map[string]string{
										"Authorization": "Basic $CLIENT_ID",
										"Content-Type":  "application/json",
									},
								},
								Response: HttpResponseConfig{
									Conditions: []ResponseCondition{
										{
											Type:       "valid",
											StatusCode: &StatusCodeMatcher{Single: intPtr(200)},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedResult: `{
				"type": "CustomHttpV2",
				"config": {
					"match_pairing": {
						"client_id": "$CLIENT_ID",
						"client_subdomain": "$CLIENT_SUBDOMAIN",
						"kind": "vendorX"
					},
					"calls": [{
						"request": {
							"endpoint": "https://$CLIENT_SUBDOMAIN.vendor.com/api/v1/token/$MATCH",
							"method": "POST",
							"headers": {
								"Authorization": "Basic $CLIENT_ID",
								"Content-Type": "application/json"
							}
						},
						"response": {
							"conditions": [
								{"type": "valid", "status_code": 200}
							]
						}
					}]
				}
			}`,
		},
		"should successfully marshal CustomHttpV2 with status code list": {
			mv: ThirdPartyActiveChecker{
				Type: ThirdPartyActiveCheckerHttpV2,
				Config: ThirdPartyActiveCheckerConfig{
					ThirdPartyActiveCheckerConfigHttpV2: &ThirdPartyActiveCheckerConfigHttpV2{
						Calls: []HttpCallConfig{
							{
								Request: HttpRequestConfig{
									Endpoint: "https://api.example.com/check",
									Method:   "GET",
								},
								Response: HttpResponseConfig{
									Conditions: []ResponseCondition{
										{
											Type:       "valid",
											StatusCode: &StatusCodeMatcher{List: []int{200, 201, 204}},
										},
										{
											Type:       "invalid",
											StatusCode: &StatusCodeMatcher{List: []int{401, 403, 404}},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedResult: `{
				"type": "CustomHttpV2",
				"config": {
					"calls": [{
						"request": {
							"endpoint": "https://api.example.com/check",
							"method": "GET"
						},
						"response": {
							"conditions": [
								{"type": "valid", "status_code": [200, 201, 204]},
								{"type": "invalid", "status_code": [401, 403, 404]}
							]
						}
					}]
				}
			}`,
		},
		"should successfully marshal CustomHttpV2 with body matchers": {
			mv: ThirdPartyActiveChecker{
				Type: ThirdPartyActiveCheckerHttpV2,
				Config: ThirdPartyActiveCheckerConfig{
					ThirdPartyActiveCheckerConfigHttpV2: &ThirdPartyActiveCheckerConfigHttpV2{
						Calls: []HttpCallConfig{
							{
								Request: HttpRequestConfig{
									Endpoint: "https://api.example.com/verify",
									Method:   "GET",
								},
								Response: HttpResponseConfig{
									Conditions: []ResponseCondition{
										{
											Type: "valid",
											RawBody: &BodyMatcher{
												Type:   BodyMatcherRegex,
												Config: stringPtr("token_valid.*true"),
											},
										},
										{
											Type: "invalid",
											RawBody: &BodyMatcher{
												Type:   BodyMatcherExactMatch,
												Config: stringPtr(`{"error":"unauthorized"}`),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedResult: `{
				"type": "CustomHttpV2",
				"config": {
					"calls": [{
						"request": {
							"endpoint": "https://api.example.com/verify",
							"method": "GET"
						},
						"response": {
							"conditions": [
								{"type": "valid", "raw_body": {"type": "Regex", "config": "token_valid.*true"}},
								{"type": "invalid", "raw_body": {"type": "ExactMatch", "config": "{\"error\":\"unauthorized\"}"}}
							]
						}
					}]
				}
			}`,
		},
		"should successfully marshal a simple PairedValidator": {
			mv: ThirdPartyActiveChecker{
				Type: ThirdPartyActiveCheckerHttpV2,
				Config: ThirdPartyActiveCheckerConfig{
					ThirdPartyActiveCheckerConfigHttpV2: &ThirdPartyActiveCheckerConfigHttpV2{
						Provides: []ThirdPartyActiveCheckerConfigPairedValidator{
							{Kind: "vendorY", Name: "client_id"},
						},
					},
				},
			},
			expectedResult: `{
				"type": "CustomHttpV2",
				"config": {
					"provides": [
						{"kind": "vendorY", "name": "client_id"}
					]
				}
			}`,
		},
		"should successfully marshal CustomHttpV2 with request body": {
			mv: ThirdPartyActiveChecker{
				Type: ThirdPartyActiveCheckerHttpV2,
				Config: ThirdPartyActiveCheckerConfig{
					ThirdPartyActiveCheckerConfigHttpV2: &ThirdPartyActiveCheckerConfigHttpV2{
						Calls: []HttpCallConfig{
							{
								Request: HttpRequestConfig{
									Endpoint: "https://api.example.com/verify",
									Method:   "GET",
									Body:     stringPtr(`{"token":"$MATCH"}`),
								},
								Response: HttpResponseConfig{
									Conditions: []ResponseCondition{
										{
											Type: "valid",
											RawBody: &BodyMatcher{
												Type:   BodyMatcherRegex,
												Config: stringPtr("token_valid.*true"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedResult: `{
				"type": "CustomHttpV2",
				"config": {
					"calls": [{
						"request": {
							"endpoint": "https://api.example.com/verify",
							"method": "GET",
							"body": "{\"token\":\"$MATCH\"}"
						},
						"response": {
							"conditions": [
								{"type": "valid", "raw_body": {"type": "Regex", "config": "token_valid.*true"}}
							]
						}
					}]
				}
			}`,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(tt.mv)
			if err != nil {
				t.Fatal("json marshalling failed")
			}

			expected := compactJSON(t, tt.expectedResult)
			if expected != string(b) {
				t.Errorf("Expected %s, got %s", expected, string(b))
			}

			var roundTripActionChecker ThirdPartyActiveChecker
			err = json.Unmarshal(b, &roundTripActionChecker)
			if err != nil {
				t.Fatal(fmt.Errorf("json unmarshalling failed %w", err))
			}
			if tt.mv.Type != roundTripActionChecker.Type {
				t.Errorf("Wrong type: Expected %#v, got %#v", tt.mv.Type, roundTripActionChecker.Type)
			}
			if roundTripActionChecker.Config.ThirdPartyActiveCheckerConfigHttpV2 == nil {
				t.Errorf("Expected httpV2 config, got nil")
			}
			if !reflect.DeepEqual(tt.mv.Config.ThirdPartyActiveCheckerConfigHttpV2, roundTripActionChecker.Config.ThirdPartyActiveCheckerConfigHttpV2) {
				t.Errorf("Wrong HttpV2 config: Expected %#v, got %#v", tt.mv.Config.ThirdPartyActiveCheckerConfigHttpV2, roundTripActionChecker.Config.ThirdPartyActiveCheckerConfigHttpV2)
			}
		})
	}
}

func Test_ThirdPartyActiveChecker_CustomHttpV2_RequestBodyRejected(t *testing.T) {
	rawChecker := `{"type":"CustomHttpV2","config":{"calls":[{"request":{"endpoint":"https://api.example.com/verify","request_body":"{\"token\":\"$MATCH\"}"},"response":{"conditions":[{"type":"valid","raw_body":{"type":"Regex","config":"token_valid.*true"}}]}}]}}`

	var checker ThirdPartyActiveChecker
	err := json.Unmarshal([]byte(rawChecker), &checker)
	if err == nil {
		t.Fatal("Expected unmarshal to fail because request_body is not supported")
	}
}

func createCustomHTTPV2Scanner(t *testing.T, config ThirdPartyActiveCheckerConfigHttpV2) *Scanner {
	t.Helper()

	scanner, err := CreateScanner([]RuleConfig{
		RegexRuleConfig{
			Id:                      "rule_secret",
			Pattern:                 "secret_[a-z0-9]+",
			MatchAction:             MatchAction{Type: MatchActionNone},
			ThirdPartyActiveChecker: *NewThirdPartyActiveCheckerHttpV2(config),
		},
	})
	if err != nil {
		t.Fatalf("Failed to build scanner: %v", err)
	}
	t.Cleanup(scanner.Delete)
	return scanner
}

func scanSingleMatchStatus(t *testing.T, scanner *Scanner, event string) MatchStatus {
	t.Helper()

	result, err := scanner.ScanWithOptions([]byte(event), ScanCallOptions{ValidateMatching: true})
	if err != nil {
		t.Fatalf("Failed to scan event: %v", err)
	}
	if len(result.Matches) != 1 {
		t.Fatalf("Expected 1 match, got %d", len(result.Matches))
	}
	return result.Matches[0].MatchStatus
}

func Test_ThirdPartyActiveChecker_CustomHttpV2_Integration_StatusCodeAndRange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/validate" {
			t.Fatalf("Expected path /validate, got %s", r.URL.Path)
		}
		token := r.URL.Query().Get("token")
		if token == "secret_ok" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"valid"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer server.Close()

	scanner := createCustomHTTPV2Scanner(t, ThirdPartyActiveCheckerConfigHttpV2{
		Calls: []HttpCallConfig{
			{
				Request: HttpRequestConfig{
					Endpoint: server.URL + "/validate?token=$MATCH",
					Method:   "GET",
				},
				Response: HttpResponseConfig{
					Conditions: []ResponseCondition{
						{
							Type:       "valid",
							StatusCode: &StatusCodeMatcher{Single: intPtr(http.StatusOK)},
						},
						{
							Type:       "invalid",
							StatusCode: &StatusCodeMatcher{Range: &StatusCodeRange{Start: 400, End: 500}},
						},
					},
				},
			},
		},
	})

	validStatus := scanSingleMatchStatus(t, scanner, "secret_ok")
	if validStatus != MatchStatusValid {
		t.Fatalf("Expected %q, got %q", MatchStatusValid, validStatus)
	}

	invalidStatus := scanSingleMatchStatus(t, scanner, "secret_bad")
	if invalidStatus != MatchStatusInvalid {
		t.Fatalf("Expected %q, got %q", MatchStatusInvalid, invalidStatus)
	}
}

func Test_ThirdPartyActiveChecker_CustomHttpV2_Integration_BodyAndHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("Expected method POST, got %s", r.Method)
		}
		if r.URL.Path != "/verify" {
			t.Fatalf("Expected path /verify, got %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("Expected Authorization header to be %q, got %q", "Bearer secret", got)
		}
		if got := r.Header.Get("X-API-Key"); got != "custom_key" {
			t.Fatalf("Expected X-API-Key header to be %q, got %q", "custom_key", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Expected body to be readable, got %v", err)
		}
		defer r.Body.Close()
		if got := string(body); got != "secret" {
			t.Fatalf("Expected body to be %q, got %q", "secret", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"success","token_valid":true}`))
	}))
	defer server.Close()

	scanner, err := CreateScanner([]RuleConfig{
		RegexRuleConfig{
			Id:          "rule_secret",
			Pattern:     "secret",
			MatchAction: MatchAction{Type: MatchActionNone},
			ThirdPartyActiveChecker: *NewThirdPartyActiveCheckerHttpV2(ThirdPartyActiveCheckerConfigHttpV2{
				Calls: []HttpCallConfig{
					{
						Request: HttpRequestConfig{
							Endpoint: server.URL + "/verify",
							Method:   "POST",
							Headers: map[string]string{
								"Authorization": "Bearer $MATCH",
								"X-API-Key":     "custom_key",
							},
							Body: stringPtr(`$MATCH`),
						},
						Response: HttpResponseConfig{
							Conditions: []ResponseCondition{
								{
									Type:       "valid",
									StatusCode: &StatusCodeMatcher{Single: intPtr(http.StatusOK)},
									RawBody: &BodyMatcher{
										Type:   BodyMatcherRegex,
										Config: stringPtr(`token_valid.*true`),
									},
								},
							},
						},
					},
				},
			}),
		},
	})
	if err != nil {
		t.Fatalf("Failed to build scanner: %v", err)
	}
	defer scanner.Delete()

	status := scanSingleMatchStatus(t, scanner, "secret")
	if status != MatchStatusValid {
		t.Fatalf("Expected %q, got %q", MatchStatusValid, status)
	}
}

func Test_ThirdPartyActiveChecker_MatchPairing_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/validate" {
			t.Errorf("Expected path /validate, got %s", r.URL.Path)
		}
		token := r.URL.Query().Get("token")
		clientID := r.URL.Query().Get("client_id")
		if token == "secret" && clientID == "cid_abc123" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	mainRule := RegexRuleConfig{
		Id:          "main",
		Pattern:     "secret",
		MatchAction: MatchAction{Type: MatchActionNone},
		ThirdPartyActiveChecker: *NewThirdPartyActiveCheckerHttpV2(ThirdPartyActiveCheckerConfigHttpV2{
			MatchPairing: &MatchPairingConfig{
				Kind: "vendorX",
				Parameters: map[string]string{
					"client_id": "$CLIENT_ID",
				},
			},
			Calls: []HttpCallConfig{
				{
					Request: HttpRequestConfig{
						Endpoint: server.URL + "/validate?token=$MATCH&client_id=$CLIENT_ID",
						Method:   "GET",
					},
					Response: HttpResponseConfig{
						Conditions: []ResponseCondition{
							{
								Type:       "valid",
								StatusCode: &StatusCodeMatcher{Single: intPtr(http.StatusOK)},
							},
							{
								Type:       "invalid",
								StatusCode: &StatusCodeMatcher{Single: intPtr(http.StatusUnauthorized)},
							},
						},
					},
				},
			},
		}),
	}

	pairedRule := RegexRuleConfig{
		Id:               "supporting",
		Pattern:          `cid_[a-z0-9]+`,
		MatchAction:      MatchAction{Type: MatchActionNone},
		IsSupportingRule: true,
		ThirdPartyActiveChecker: *NewThirdPartyActiveCheckerHttpV2(ThirdPartyActiveCheckerConfigHttpV2{
			Provides: []ThirdPartyActiveCheckerConfigPairedValidator{
				{
					Kind: "vendorX",
					Name: "client_id",
				},
			},
		}),
	}

	scanner, err := CreateScanner([]RuleConfig{mainRule, pairedRule})
	if err != nil {
		t.Fatalf("Failed to build scanner: %v", err)
	}
	defer scanner.Delete()

	t.Run("valid secret with correct paired client_id resolves to Valid", func(t *testing.T) {
		result, err := scanner.ScanEventsMapWithOptions(map[string]interface{}{
			"token":     "secret",
			"client_id": "cid_abc123",
		}, ScanCallOptions{ValidateMatching: true})
		if err != nil {
			t.Fatalf("Failed to scan event: %v", err)
		}

		if len(result.Matches) != 1 {
			t.Fatalf("Expected 1 match, got %d", len(result.Matches))
		}
		if result.Matches[0].MatchStatus != MatchStatusValid {
			t.Fatalf("Expected main rule match status %q, got %q", MatchStatusValid, result.Matches[0].MatchStatus)
		}
	})

	t.Run("secret without paired client_id resolves to MissingDependentMatch", func(t *testing.T) {
		result, err := scanner.ScanEventsMapWithOptions(map[string]interface{}{
			"token": "secret",
		}, ScanCallOptions{ValidateMatching: true})
		if err != nil {
			t.Fatalf("Failed to scan event: %v", err)
		}

		if len(result.Matches) != 1 {
			t.Fatalf("Expected 1 match, got %d", len(result.Matches))
		}
		if result.Matches[0].MatchStatus != MatchStatusMissingDependentMatch {
			t.Fatalf("Expected %q when paired validator not present, got %q", MatchStatusMissingDependentMatch, result.Matches[0].MatchStatus)
		}
	})
}
