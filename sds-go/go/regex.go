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

// ValidateRegex validates a regex pattern and returns any error message.
// Returns (true, nil) if the regex is valid, or (false, error) if invalid.
func ValidateRegex(regex string) (bool, error) {
	cRegex := C.CString(regex)
	defer C.free(unsafe.Pointer(cRegex))

	result := C.validate_regex(cRegex, nil)
	if result == nil {
		return true, nil
	}

	errorMsg := C.GoString(result)
	C.free_string(result)
	return false, fmt.Errorf("invalid regex: %s", errorMsg)
}

// AstNode represents a node in the regex abstract syntax tree.
// Each node provides detailed information about a specific part of the regex pattern.
type AstNode struct {
	// NodeType is the type of syntax element (e.g., "Literal", "Alternation", "Capturing Group")
	NodeType string `json:"node_type"`

	// Description is a human-readable explanation of what this node does
	Description string `json:"description"`

	// Start is the character position where this node begins in the original pattern (for highlighting)
	Start int `json:"start"`

	// End is the character position where this node ends in the original pattern (for highlighting)
	End int `json:"end"`

	// Children contains nested AST nodes for complex patterns
	Children []AstNode `json:"children,omitempty"`

	// Properties contains additional metadata about the node
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// RegexExplanation contains the result of explaining a regex pattern.
// If the regex is invalid, IsValid will be false and Error will contain the error message.
type RegexExplanation struct {
	// IsValid indicates whether the regex pattern was successfully parsed
	IsValid bool `json:"is_valid"`

	// Error contains the error message if the regex is invalid
	Error *string `json:"error,omitempty"`

	// Tree is the root node of the Abstract Syntax Tree if the regex is valid
	Tree *AstNode `json:"tree,omitempty"`
}

// ExplainRegex parses a regex pattern and returns its Abstract Syntax Tree (AST)
// along with human-readable descriptions of each node.
func ExplainRegex(regex string) (RegexExplanation, error) {
	cRegex := C.CString(regex)
	defer C.free(unsafe.Pointer(cRegex))

	result := C.explain_regex(cRegex, nil)
	if result == nil {
		return RegexExplanation{
			IsValid: false,
			Error:   stringPtr("Failed to explain regex"),
		}, nil
	}

	jsonStr := C.GoString(result)
	C.free_string(result)

	var explanation RegexExplanation
	if err := json.Unmarshal([]byte(jsonStr), &explanation); err != nil {
		return RegexExplanation{
			IsValid: false,
			Error:   stringPtr("Failed to parse explanation JSON"),
		}, err
	}

	return explanation, nil
}

func stringPtr(s string) *string {
	return &s
}
