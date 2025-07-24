package dd_sds

import (
	"testing"
)

func TestValidateRegex(t *testing.T) {
	// Test valid regex
	_, err := ValidateRegex("hello")
	if err != nil {
		t.Fatal(err)
	}

	// Test invalid regex to ensure memory is properly freed
	_, err = ValidateRegex("[")
	if err == nil {
		t.Fatal("Expected error for invalid regex")
	}
}
