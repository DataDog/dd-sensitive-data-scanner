package dd_sds

import (
	"bytes"
	"encoding/binary"
	//"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unsafe"
)

/*
#include <stdlib.h>
#include <dd_sds.h>
*/
import "C"

var (
	ErrUnknown            error = fmt.Errorf("unknown error")
	ErrInvalidRegex       error = fmt.Errorf("invalid regex")
	ErrInvalidKeywords    error = fmt.Errorf("invalid keywords")
	ErrInvalidMatchAction error = fmt.Errorf("invalid match action")
)

// Scanner wraps an SDS scanner.
// See `CreateScanner` to create one providing SDS rules.
// See `Scan`, `ScanEventsList` or a `ScanEventsMap` for usage.
type Scanner struct {
	// Id of this scanner generated by the SDS library when the scanner is created.
	Id int64
	// They are stored on creation for read-only usage.
	//Rules []Rule
}

// ScanResult contains a Scan result.
type ScanResult struct {
	// String Event contains the event after the scan.
	// In case of map input it contains the mutated string. (The input event is mutated in place)
	// If `Mutated` is true:
	//   * it contains the processed event after redaction.
	// If `Mutated` is false:
	//   * it contains the original event, unchanged.
	Event []byte
	scanResult
}

type scanResult struct {
	// Mutated indicates if the processed event has been
	// mutated or not (e.g. redacted).
	Mutated bool
	// Matches contains all rule matches if any.
	Matches []RuleMatch
}

// CreateScanner creates a scanner in the underlying SDS shared library. The library
// only returns an ID to then address what scanner to use on Scan calls. This ID is
// stored in the Scanner Go object for convenience. See `Scan` to process events.
// The rules used to create the Scanner are stored as a read-only information in the
// returned Scanner.
func CreateScanner(ruleConfigs []RuleConfig) (*Scanner, error) {

	ruleList := CreateRuleList()

	for _, ruleConfig := range ruleConfigs {
		rule, err := ruleConfig.CreateRule()
		if err != nil {
			return nil, err
		}
		ruleList.AppendRule(rule)
	}

	var errorString *C.char
	id := C.create_scanner(C.long(ruleList.nativePtr), &errorString, C.bool(false) /* should_keywords_match_event_paths */)

	if id < 0 {
		switch id {
		//  see rust/native/create_scanner.rs for the mapping.
		case -1: // rust unknown error
			return nil, ErrUnknown
		case -2: // rust: CreateScannerError::InvalidRegex
			return nil, ErrInvalidRegex
		case -3: // rust: CreateScannerError::InvalidKeywords
			return nil, ErrInvalidKeywords
		case -4: // rust: CreateScannerError::InvalidMatchAction
			return nil, ErrInvalidMatchAction
		case -5: // rust panic
			if errorString != nil {
				defer C.free_string(errorString)
				return nil, fmt.Errorf("internal panic: %v", C.GoString(errorString))
			} else {
				return nil, fmt.Errorf("internal panic")
			}
		}

		return nil, ErrUnknown
	}

	return &Scanner{
		Id: int64(id),
		//Rules: rules,
	}, nil
}

// Delete deletes the instance of the current Scanner.
// The current Scanner should not be reused.
func (s *Scanner) Delete() {
	C.delete_scanner(C.long(s.Id))
	s.Id = 0
	//s.Rules = nil
}

func (s *Scanner) lowLevelScan(encodedEvent []byte) ([]byte, error) {
	cdata := C.CBytes(encodedEvent)
	defer C.free(cdata)

	var retsize int64
	var retcap int64
	var errorString *C.char

	rvdata := C.scan(C.long(s.Id), cdata, C.long(len(encodedEvent)), (*C.long)(unsafe.Pointer(&retsize)), (*C.long)(unsafe.Pointer(&retcap)), &errorString)
	if errorString != nil {
		defer C.free_string(errorString)
		return nil, fmt.Errorf("internal panic: %v", C.GoString(errorString))
	}

	// nothing has matched, ignore the returned object
	if retsize <= 0 || retcap <= 0 {
		return nil, nil
	}

	// otherwise we received data initially owned by rust, once we've used it,
	// use `free_vec` to let know rust it can drop this memory.
	defer C.free_vec(rvdata, C.long(retsize), C.long(retcap))

	// Note that in the Go 1.21 documentation, GoBytes is part of:
	// > A few special functions convert between Go and C types by making copies of the data.
	// Meaning that the data in `rv` is a copy owned by Go of what's in rvdata.
	response := C.GoBytes(unsafe.Pointer(rvdata), C.int(retsize))

	return response, nil
}

func (s *Scanner) scanEncodedMapEvent(encodedEvent []byte, event map[string]interface{}) (ScanResult, error) {
	response, err := s.lowLevelScan(encodedEvent)
	if err != nil {
		return ScanResult{}, err
	}

	// prepare and return the result
	result, err := decodeEventMapResponse(response, event)
	if err != nil {
		return ScanResult{}, fmt.Errorf("scan: %v", err)
	}

	return result, nil
}

func (s *Scanner) scanEncodedStringEvent(encodedEvent []byte) (ScanResult, error) {
	response, err := s.lowLevelScan(encodedEvent)
	if err != nil {
		return ScanResult{}, err
	}

	// prepare and return the result
	result, err := decodeResponse(response)

	if err != nil {
		return ScanResult{}, fmt.Errorf("scan: %v", err)
	}

	return result, nil
}

// Scan sends the string event to the SDS shared library for processing.
func (s *Scanner) Scan(event []byte) (ScanResult, error) {
	encodedEvent := make([]byte, 0)
	encodedEvent, err := encodeStringEvent(event, encodedEvent)
	if err != nil {
		return ScanResult{}, err
	}

	var result ScanResult
	if result, err = s.scanEncodedStringEvent(encodedEvent); err != nil {
		return ScanResult{}, err
	}

	// if not mutated, return the original event.
	if !result.Mutated {
		result.Event = event
	}

	return result, err
}

// ScanEventsMap sends a map event to the SDS shared library for processing.
// In case of mutation, event is updated in place.
// The returned ScanResult contains the mutated string in the Event attribute (not the event)
func (s *Scanner) ScanEventsMap(event map[string]interface{}) (ScanResult, error) {
	encodedEvent := make([]byte, 0)
	encodedEvent, err := encodeMapEvent(event, encodedEvent)
	if err != nil {
		return ScanResult{}, err
	}

	return s.scanEncodedMapEvent(encodedEvent, event)
}

// encodeStringEvent encodes teh given event to send it to the SDS shared library.
func encodeStringEvent(log []byte, result []byte) ([]byte, error) {
	result = append(result, byte(3)) // string data
	result = binary.BigEndian.AppendUint32(result, uint32(len(log)))
	result = append(result, log...)
	return result, nil
}

func encodeValueRecursive(v interface{}, result []byte) ([]byte, error) {
	switch v := v.(type) {
	case string:
		return encodeStringEvent([]byte(v), result)
	case map[string]interface{}:
		return encodeMapEvent(v, result)
	case []interface{}:
		return encodeListEvent(v, result)
	default:
		return result, fmt.Errorf("encodeValueRecursive: unknown type %T", v)
	}

}

func encodeMapEvent(event map[string]interface{}, result []byte) ([]byte, error) {
	for k, v := range event {
		// // push path field
		result = append(result, 0)                                     // push map type
		result = binary.BigEndian.AppendUint32(result, uint32(len(k))) // length of the key
		result = append(result, []byte(k)...)                          // key
		var err error = nil
		result, err = encodeValueRecursive(v, result)
		if err != nil {
			return result, err
		}
		// pop index
		result = append(result, 2) // pop  path index
	}
	return result, nil
}

func encodeListEvent(log []interface{}, result []byte) ([]byte, error) {
	for idx, v := range log {
		// push path field
		result = append(result, 1)                                  // push index
		result = binary.BigEndian.AppendUint32(result, uint32(idx)) // index
		var err error = nil
		result, err = encodeValueRecursive(v, result)
		if err != nil {
			return result, err
		}
		// pop index
		result = append(result, 2) // pop  path index
	}
	return result, nil
}

func parseReplacementType(replacementType string) ReplacementType {
	switch strings.ToLower(replacementType) {
	case "placeholder":
		return ReplacementTypePlaceholder
	case "hash":
		return ReplacementTypeHash
	case "partial_beginning":
		return ReplacementTypePartialStart
	case "partial_end":
		return ReplacementTypePartialEnd
	default:
		return ReplacementTypeNone
	}
}

func decodeMatchResponse(result *ScanResult, buf *bytes.Buffer) {
	// starts with a rule ID
	ruleIdx := binary.BigEndian.Uint32(buf.Next(4))

	// then a path
	path := nextString(buf)

	// then a replacement type
	// TODO(https://datadoghq.atlassian.net/browse/SDS-301): implement replacement type
	//replacementType := nextString(buf)
	replacementType := parseReplacementType(string(nextString(buf)))

	startIndex := binary.BigEndian.Uint32(buf.Next(4))
	endIndexExclusive := binary.BigEndian.Uint32(buf.Next(4))
	shiftOffset := int32(binary.BigEndian.Uint32(buf.Next(4)))

	result.Matches = append(result.Matches, RuleMatch{
		RuleIdx:           ruleIdx,
		Path:              string(path),
		ReplacementType:   replacementType,
		StartIndex:        startIndex,
		EndIndexExclusive: endIndexExclusive,
		ShiftOffset:       shiftOffset,
	})
}

func decodeEventMapResponse(rawData []byte, event map[string]interface{}) (ScanResult, error) {
	buf := bytes.NewBuffer(rawData)

	var result ScanResult

	for buf.Len() > 0 {
		typ, err := buf.ReadByte()
		if err != nil {
			return ScanResult{}, fmt.Errorf("decodeEventMapResponse: %v", err)
		}

		switch typ {
		case 4: // Mutation
			result.Mutated = true
			if result.Event, err = applyStringMutationMap(buf, event); err != nil {
				return ScanResult{}, fmt.Errorf("applyStringMutationMap: %v", err)
			}
		case 5: // Match
			decodeMatchResponse(&result, buf)
		default:
			return ScanResult{}, fmt.Errorf("decodeEventMapResponse: can't decode response, unknown byte marker: %x", typ)
		}
	}

	return result, nil
}

// decodeResponse reads the binary response returned by the SDS shared library
// on a `scan` call.
func decodeResponse(rawData []byte) (ScanResult, error) {
	buf := bytes.NewBuffer(rawData)

	var result ScanResult

	for buf.Len() > 0 {
		typ, err := buf.ReadByte()
		if err != nil {
			return ScanResult{}, fmt.Errorf("decodeResponse: %v", err)
		}

		switch typ {
		case 4: // Mutation
			result.Mutated = true
			if result.Event, err = decodeMutation(buf); err != nil {
				return ScanResult{}, fmt.Errorf("decodeResponse: %v", err)
			}
		case 5: // Match
			decodeMatchResponse(&result, buf)
		default:
			return ScanResult{}, fmt.Errorf("decodeResponse: can't decode response, unknown byte marker: %x", typ)
		}
	}

	return result, nil
}

// nextString using this format:
// * 8 bytes: string size
// * string size: the string
// This method DO NOT copy data around but re-use the underlying slicebuffer instead.
// Best usage si to use it after a call to `GoBytes` which takes care of copying
// the data in the Go world.
func nextString(buf *bytes.Buffer) []byte {
	size := binary.BigEndian.Uint32(buf.Next(4))
	rv := buf.Next(int(size))
	return rv
}

func nextInt(buf *bytes.Buffer) int {
	return int(binary.BigEndian.Uint32(buf.Next(4)))
}

func applyStringMutationMap(buf *bytes.Buffer, event map[string]interface{}) ([]byte, error) {
	tag, err := buf.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("decodeMapMutation: %v", err)
	}
	return applyStringMutationMapWithTag(buf, event, tag)
}

func applyStringMutationMapWithTag(buf *bytes.Buffer, event map[string]interface{}, tag byte) ([]byte, error) {
	if tag != 0 {
		return nil, fmt.Errorf("decodeMapMutation: expected path field")
	}
	fieldName := nextString(buf)

	nextTag, err := buf.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("decodeMapMutation: %v", err)
	}
	if nextTag == 3 {
		// new string value
		res := nextString(buf)
		// Update the event with the new value.
		event[string(fieldName)] = string(res)
		return res, nil
	} else {
		return applyStringMutation(buf, event[string(fieldName)], nextTag)
	}
}

func applyStringMutationListWithTag(buf *bytes.Buffer, event []interface{}, tag byte) ([]byte, error) {
	if tag != 1 {
		return nil, fmt.Errorf("decodeListMutation: expected path index")
	}
	indexInArray := nextInt(buf)

	nextTag, err := buf.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("decodeListMutation: %v", err)
	}

	if nextTag == 3 {
		// new string value
		res := nextString(buf)
		// Update the event with the new value.
		event[indexInArray] = string(res)
		return res, nil
	} else {
		// rewind 1 byte in buf as marker is used by applyStringMutation
		return applyStringMutation(buf, event[indexInArray], nextTag)
	}
}

func applyStringMutation(buf *bytes.Buffer, value interface{}, tag byte) ([]byte, error) {
	switch reflect.TypeOf(value).Kind() {
	case reflect.Map:
		return applyStringMutationMapWithTag(buf, value.(map[string]interface{}), tag)
	case reflect.Slice:
		return applyStringMutationListWithTag(buf, value.([]interface{}), tag)
	}
	return nil, fmt.Errorf("applyStringMutation: unknown type %T", value)
}

// decodeMutation returns the result of a mutation done by the SDS shared library.
// TODO(remy): only the redacted/processed event is used, implement what's necessary
// to return Path/Segment information.
func decodeMutation(buf *bytes.Buffer) ([]byte, error) {
	// first, we will be reading a possibly empty path
	//   if we see a '0' byte value, we are reading a field
	//   if we see a '1' byte value, we are reading an index
	// if we see a '3' byte value, we are not reading a path anymore, but a content string
	// of the possibly redacted event.
	done := false
	var processed []byte
	for !done {
		marker, err := buf.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("decodeMutation: %v", err)
		}
		switch marker {
		case 0:
			// reading a field
			// TODO(remy): not implemented: use the Path/Segments information
			// and return it in the Go bindings Scan call.
			nextString(buf)
		case 1:
			// reading an index
			// TODO(remy): not implemented: use the Path/Segments information
			// and return it in the Go bindings Scan call.
			binary.BigEndian.Uint32(buf.Next(4))
		case 3:
			// reading content string
			processed = nextString(buf)
			done = true
		}
	}
	return processed, nil
}
