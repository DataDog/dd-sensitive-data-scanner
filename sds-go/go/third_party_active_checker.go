package dd_sds

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type ThirdPartyActiveCheckerType string

const (
	ThirdPartyActiveCheckerAws    = ThirdPartyActiveCheckerType("Aws")
	ThirdPartyActiveCheckerHttp   = ThirdPartyActiveCheckerType("CustomHttp")
	ThirdPartyActiveCheckerHttpV2 = ThirdPartyActiveCheckerType("CustomHttpV2")
)

type ThirdPartyActiveChecker struct {
	Type   ThirdPartyActiveCheckerType   `json:"type"`
	Config ThirdPartyActiveCheckerConfig `json:"config"`
}

type ThirdPartyActiveCheckerConfig struct {
	*ThirdPartyActiveCheckerConfigAws
	*ThirdPartyActiveCheckerConfigHttp
	*ThirdPartyActiveCheckerConfigHttpV2
}

func NewThirdPartyActiveCheckerAws(kind ThirdPartyActiveCheckerKind, awsStsEndpoint string, timeout Duration) *ThirdPartyActiveChecker {
	return &ThirdPartyActiveChecker{
		Type: ThirdPartyActiveCheckerAws,
		Config: ThirdPartyActiveCheckerConfig{
			ThirdPartyActiveCheckerConfigAws: &ThirdPartyActiveCheckerConfigAws{
				Kind:           kind,
				AwsStsEndpoint: awsStsEndpoint,
				Timeout:        timeout,
			},
		},
	}
}

func NewThirdPartyActiveCheckerHttp(endpoint string, hosts []string, method ThirdPartyActiveCheckerHttpMethod, requestHeaders map[string]string, validHttpStatusCodes []StatusCodeRange, invalidHttpStatusCodes []StatusCodeRange, timeout int) *ThirdPartyActiveChecker {
	return &ThirdPartyActiveChecker{
		Type: ThirdPartyActiveCheckerHttp,
		Config: ThirdPartyActiveCheckerConfig{
			ThirdPartyActiveCheckerConfigHttp: &ThirdPartyActiveCheckerConfigHttp{
				Endpoint:               endpoint,
				Hosts:                  hosts,
				Method:                 method,
				RequestHeader:          requestHeaders,
				ValidHttpStatusCodes:   validHttpStatusCodes,
				InvalidHttpStatusCodes: invalidHttpStatusCodes,
				Timeout:                timeout,
			},
		},
	}
}

func NewThirdPartyActiveCheckerHttpV2(config ThirdPartyActiveCheckerConfigHttpV2) *ThirdPartyActiveChecker {
	return &ThirdPartyActiveChecker{
		Type: ThirdPartyActiveCheckerHttpV2,
		Config: ThirdPartyActiveCheckerConfig{
			ThirdPartyActiveCheckerConfigHttpV2: &config,
		},
	}
}

func (m ThirdPartyActiveChecker) IsThirdPartyActiveCheckerConfigAws() bool {
	return m.Config.ThirdPartyActiveCheckerConfigAws != nil
}

func (m ThirdPartyActiveChecker) IsThirdPartyActiveCheckerConfigHttp() bool {
	return m.Config.ThirdPartyActiveCheckerConfigHttp != nil
}

func (m ThirdPartyActiveChecker) IsThirdPartyActiveCheckerConfigHttpV2() bool {
	return m.Config.ThirdPartyActiveCheckerConfigHttpV2 != nil
}

type ThirdPartyActiveCheckerConfigAws struct {
	Kind           ThirdPartyActiveCheckerKind `json:"kind"`
	AwsStsEndpoint string                      `json:"aws_sts_endpoint"`
	Timeout        Duration                    `json:"timeout"`
}

type ThirdPartyActiveCheckerKind string

const (
	ThirdPartyActiveCheckerAwsId      = ThirdPartyActiveCheckerKind("AwsId")
	ThirdPartyActiveCheckerAwsSecret  = ThirdPartyActiveCheckerKind("AwsSecret")
	ThirdPartyActiveCheckerAwsSession = ThirdPartyActiveCheckerKind("AwsSession")
)

type ThirdPartyActiveCheckerHttpMethod string

const (
	MethodGet    = ThirdPartyActiveCheckerHttpMethod("GET")
	MethodPost   = ThirdPartyActiveCheckerHttpMethod("POST")
	MethodPut    = ThirdPartyActiveCheckerHttpMethod("PUT")
	MethodDelete = ThirdPartyActiveCheckerHttpMethod("DELETE")
	MethodPatch  = ThirdPartyActiveCheckerHttpMethod("PATCH")
)

type StatusCodeRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type Duration struct {
	Seconds uint64 `json:"secs"`
	Nanos   uint64 `json:"nanos"`
}

type ThirdPartyActiveCheckerConfigHttp struct {
	Endpoint               string                            `json:"endpoint"`
	Hosts                  []string                          `json:"hosts,omitempty"`
	Method                 ThirdPartyActiveCheckerHttpMethod `json:"http_method"`
	RequestHeader          map[string]string                 `json:"request_headers"`
	ValidHttpStatusCodes   []StatusCodeRange                 `json:"valid_http_status_code"`
	InvalidHttpStatusCodes []StatusCodeRange                 `json:"invalid_http_status_code"`
	Timeout                int                               `json:"timeout_seconds"`
}

type ThirdPartyActiveCheckerConfigHttpV2 struct {
	MatchPairing *MatchPairingConfig                            `json:"match_pairing,omitempty"`
	Provides     []ThirdPartyActiveCheckerConfigPairedValidator `json:"provides,omitempty"`
	Calls        []HttpCallConfig                               `json:"calls,omitempty"`
}

type ThirdPartyActiveCheckerConfigPairedValidator struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type MatchPairingConfig struct {
	Kind       string            `json:"kind"`
	Parameters map[string]string `json:"-"`
}

func (m MatchPairingConfig) MarshalJSON() ([]byte, error) {
	result := make(map[string]interface{})
	result["kind"] = m.Kind
	for k, v := range m.Parameters {
		result[k] = v
	}
	return json.Marshal(result)
}

func (m *MatchPairingConfig) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if kind, ok := raw["kind"].(string); ok {
		m.Kind = kind
		delete(raw, "kind")
	}

	m.Parameters = make(map[string]string)
	for k, v := range raw {
		if str, ok := v.(string); ok {
			m.Parameters[k] = str
		}
	}

	return nil
}

type HttpCallConfig struct {
	Request  HttpRequestConfig  `json:"request"`
	Response HttpResponseConfig `json:"response"`
}

type HttpRequestConfig struct {
	Endpoint string            `json:"endpoint"`
	Method   string            `json:"method"`
	Hosts    []string          `json:"hosts,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     *string           `json:"body,omitempty"`
	Timeout  *Duration         `json:"timeout,omitempty"`
}

type HttpResponseConfig struct {
	Conditions []ResponseCondition `json:"conditions"`
}

type ResponseCondition struct {
	Type       string                  `json:"type"`
	StatusCode *StatusCodeMatcher      `json:"status_code,omitempty"`
	RawBody    *BodyMatcher            `json:"raw_body,omitempty"`
	Body       map[string]*BodyMatcher `json:"body,omitempty"`
}

type StatusCodeMatcher struct {
	Single *int             `json:"-"`
	List   []int            `json:"-"`
	Range  *StatusCodeRange `json:"-"`
}

type BodyMatcherType string

const (
	BodyMatcherPresent    BodyMatcherType = "Present"
	BodyMatcherExactMatch BodyMatcherType = "ExactMatch"
	BodyMatcherRegex      BodyMatcherType = "Regex"
)

type BodyMatcher struct {
	Type   BodyMatcherType `json:"type"`
	Config *string         `json:"config,omitempty"`
}

func (t ThirdPartyActiveChecker) MarshalJSON() ([]byte, error) {
	if t.Type == "" {
		return []byte("null"), nil
	}

	type Alias ThirdPartyActiveChecker
	return json.Marshal((Alias)(t))
}

func (m ThirdPartyActiveCheckerConfig) MarshalJSON() ([]byte, error) {
	if m.ThirdPartyActiveCheckerConfigAws != nil {
		return json.Marshal(m.ThirdPartyActiveCheckerConfigAws)
	}
	if m.ThirdPartyActiveCheckerConfigHttpV2 != nil {
		return json.Marshal(m.ThirdPartyActiveCheckerConfigHttpV2)
	}
	return json.Marshal(m.ThirdPartyActiveCheckerConfigHttp)
}

func (m StatusCodeMatcher) MarshalJSON() ([]byte, error) {
	if m.Single != nil {
		return json.Marshal(*m.Single)
	}
	if m.List != nil {
		return json.Marshal(m.List)
	}
	if m.Range != nil {
		return json.Marshal(m.Range)
	}
	return []byte("null"), nil
}

func (m *StatusCodeMatcher) UnmarshalJSON(data []byte) error {
	var single int
	if err := json.Unmarshal(data, &single); err == nil {
		m.Single = &single
		return nil
	}

	var list []int
	if err := json.Unmarshal(data, &list); err == nil {
		m.List = list
		return nil
	}

	var rangeObj StatusCodeRange
	if err := json.Unmarshal(data, &rangeObj); err == nil {
		m.Range = &rangeObj
		return nil
	}

	return fmt.Errorf("unable to unmarshal StatusCodeMatcher from: %s", string(data))
}

func (m ThirdPartyActiveCheckerConfigAws) MarshalJSON() ([]byte, error) {
	o := map[string]interface{}{
		"kind": string(m.Kind),
	}

	if m.Kind == ThirdPartyActiveCheckerAwsSecret {
		o["aws_sts_endpoint"] = m.AwsStsEndpoint
		o["timeout"] = m.Timeout
	}

	return json.Marshal(o)
}

func (m *ThirdPartyActiveChecker) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*m = ThirdPartyActiveChecker{}
		return nil
	}

	var rawMap struct {
		Type   string          `json:"type"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(rawMap.Config))
	decoder.DisallowUnknownFields()

	switch rawMap.Type {
	case "Aws":
		m.Type = ThirdPartyActiveCheckerAws
		var config ThirdPartyActiveCheckerConfigAws
		if err := decoder.Decode(&config); err != nil {
			return err
		}
		m.Config = ThirdPartyActiveCheckerConfig{ThirdPartyActiveCheckerConfigAws: &config}
	case "CustomHttp":
		m.Type = ThirdPartyActiveCheckerHttp
		var config ThirdPartyActiveCheckerConfigHttp
		if err := decoder.Decode(&config); err != nil {
			return err
		}
		m.Config = ThirdPartyActiveCheckerConfig{ThirdPartyActiveCheckerConfigHttp: &config}
	case "CustomHttpV2":
		m.Type = ThirdPartyActiveCheckerHttpV2
		var config ThirdPartyActiveCheckerConfigHttpV2
		if err := decoder.Decode(&config); err != nil {
			return err
		}
		m.Config = ThirdPartyActiveCheckerConfig{ThirdPartyActiveCheckerConfigHttpV2: &config}
	default:
		return fmt.Errorf("unknown third party active checker type: %s", rawMap.Type)
	}

	return nil
}
