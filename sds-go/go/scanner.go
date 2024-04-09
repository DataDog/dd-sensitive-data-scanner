package sds

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"unsafe"
)

/*
#cgo LDFLAGS: -L../rust/target/release -lsds_go
#include <stdlib.h>
#include "sds.h"
*/
import "C"

var (
	UnknownError       error = fmt.Errorf("unknown error")
	InvalidRegex       error = fmt.Errorf("invalid regex")
	InvalidKeywords    error = fmt.Errorf("invalid keywords")
	InvalidMatchAction error = fmt.Errorf("invalid match action")
)

type Scanner struct {
	// Id of this scanner generated by the SDS library when the scanner is created.
	Id int64
	// They are stored on creation for read-only usage.
	Rules []Rule
}

// CreateScanner creates a scanner in the underlying SDS shared library. The library
// only returns an ID to then address what scanner to use on Scan calls. This ID is
// stored in the Scanner Go object for convenience. See `Scan` to process events.
// The rules used to create the Scanner are stored as a read-only information in the
// returned Scanner.
func CreateScanner(rules []Rule) (*Scanner, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("No rules provided")
	}

	data, err := json.Marshal(rules)
	if err != nil {
		return nil, err
	}

	cdata := C.CString(string(data)) // this call adds the 0, memory has to be freed
	defer C.free(unsafe.Pointer(cdata))

	var errorString *C.char

	id := C.create_scanner(cdata, &errorString)

	if id < 0 {
		switch id {
		//  see rust/native/create_scanner.rs for the mapping.
		case -1: // rust unknown error
			return nil, UnknownError
		case -2: // rust: CreateScannerError::InvalidRegex
			return nil, InvalidRegex
		case -3: // rust: CreateScannerError::InvalidKeywords
			return nil, InvalidKeywords
		case -4: // rust: CreateScannerError::InvalidMatchAction
			return nil, InvalidMatchAction
		case -5: // rust panic
			if errorString != nil {
				defer C.free_string(errorString)
				return nil, fmt.Errorf("Internal panic: %v", C.GoString(errorString))
			} else {
				return nil, fmt.Errorf("Internal panic")
			}
		}

		return nil, UnknownError
	}

	return &Scanner{
		Id:    int64(id),
		Rules: rules,
	}, nil
}

// Delete deletes the instance of the current Scanner.
// The current Scanner should not be reused.
func (s *Scanner) Delete() {
	C.delete_scanner(C.long(s.Id))
	s.Id = 0
	s.Rules = nil
}

func (s *Scanner) scanEncodedEvent(encodedEvent []byte) ([]byte, []RuleMatch, error) {
	cdata := C.CBytes(encodedEvent)
	defer C.free(cdata)

	var retsize int64
	var retcap int64
	var errorString *C.char

	rvdata := C.scan(C.long(s.Id), cdata, C.long(len(encodedEvent)), (*C.long)(unsafe.Pointer(&retsize)), (*C.long)(unsafe.Pointer(&retcap)), &errorString)
	if errorString != nil {
		defer C.free_string(errorString)
		return nil, nil, fmt.Errorf("Internal panic: %v", C.GoString(errorString))
	}

	// nothing has matched, ignore the returned object
	if retsize <= 0 || retcap <= 0 {
		return nil, []RuleMatch{}, nil
	}

	// otherwise we received data initially owned by rust, once we've used it,
	// use `free_vec` to let know rust it can drop this memory.
	defer C.free_vec(rvdata, C.long(retsize), C.long(retcap))

	rv := []byte{}
	// Note that in the Go 1.21 documentation, GoBytes is part of:
	// > A few special functions convert between Go and C types by making copies of the data.
	// Meaning that the data in `rv` is a copy owned by Go of what's in rvdata.
	rv = C.GoBytes(unsafe.Pointer(rvdata), C.int(retsize))

	processed, ruleMatches, err := decodeResponse(rv)
	if err != nil {
		return nil, nil, fmt.Errorf("Scan: %v", err)
	}

	return processed, ruleMatches, nil
}

// Scan sends the string event to the SDS shared library for processing.
// Returned values:
//   - the processed log if any mutation happened
//   - rules matches if any rule has matched
//   - a possible error
//
// TODO(remy): implement ScanEventsMap, ScanEventsList
func (s *Scanner) Scan(event []byte) ([]byte, []RuleMatch, error) {
	encodedEvent := make([]byte, 0)
	encodedEvent, err := encodeStringEvent(event, encodedEvent)
	if err != nil {
		return nil, nil, err
	}
	return s.scanEncodedEvent(encodedEvent)
}

func (s *Scanner) ScanEventsMap(event map[string]interface{}) ([]byte, []RuleMatch, error) {
	encodedEvent := make([]byte, 0)
	encodedEvent, err := encodeMapEvent(event, encodedEvent)
	if err != nil {
		return nil, nil, err
	}
	return s.scanEncodedEvent(encodedEvent)
}

func (s *Scanner) ScanEventsList(event []interface{}) ([]byte, []RuleMatch, error) {
	encodedEvent := make([]byte, 0)
	encodedEvent, err := encodeListEvent(event, encodedEvent)
	if err != nil {
		return nil, nil, err
	}
	return s.scanEncodedEvent(encodedEvent)
}

// encodeStringEvent encodes teh given event to send it to the SDS shared library.
// TODO(remy): implement encodeMapEvent, encodeListEvent
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

// decodeResponse reads the binary response returned by the SDS shared library
// on a `scan` call.
// Returned values are:
//   - the processed log if any mutation happened
//   - rules matches if any rule has matched
//   - a possible error
func decodeResponse(rawData []byte) ([]byte, []RuleMatch, error) {
	buf := bytes.NewBuffer(rawData)

	var processed []byte
	var ruleMatches []RuleMatch

	for buf.Len() > 0 {
		typ, err := buf.ReadByte()
		if err != nil {
			return nil, nil, fmt.Errorf("decodeResponse: %v", err)
		}

		switch typ {
		case 4: // Mutation
			if processed, err = decodeMutation(buf); err != nil {
				return nil, nil, fmt.Errorf("decodeResponse: %v", err)
			}
		case 5: // Match
			// starts with a rule ID
			ruleIdx := binary.BigEndian.Uint32(buf.Next(4))

			// then a path
			path := decodeString(buf)

			// then a replacement type
			// TODO(remy): implement me
			//replacementType := decodeString(buf)
			decodeString(buf)

			startIndex := binary.BigEndian.Uint32(buf.Next(4))
			endIndexExclusive := binary.BigEndian.Uint32(buf.Next(4))
			shiftOffset := binary.BigEndian.Uint32(buf.Next(4))

			ruleMatches = append(ruleMatches, RuleMatch{
				RuleIdx:           ruleIdx,
				Path:              string(path),
				StartIndex:        startIndex,
				EndIndexExclusive: endIndexExclusive,
				ShiftOffset:       shiftOffset,
			})
		default:
			return nil, nil, fmt.Errorf("decodeResponse: can't decode response, unknown byte marker: %x", typ)
		}
	}

	return processed, ruleMatches, nil
}

// decodeString using this format:
// * 8 bytes: string size
// * string size: the string
// This method DO NOT copy data around but re-use the underlying sliceuffer instead.
// Best usage si to use it after a call to `GoBytes` which takes care of copying
// the data in the Go world.
func decodeString(buf *bytes.Buffer) []byte {
	size := binary.BigEndian.Uint32(buf.Next(4))
	rv := buf.Next(int(size))
	return rv
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
			decodeString(buf)
		case 1:
			// reading an index
			// TODO(remy): not implemented: use the Path/Segments information
			// and return it in the Go bindings Scan call.
			binary.BigEndian.Uint32(buf.Next(4))
		case 3:
			// reading content string
			processed = decodeString(buf)
			done = true
			break
		}
	}
	return processed, nil
}
