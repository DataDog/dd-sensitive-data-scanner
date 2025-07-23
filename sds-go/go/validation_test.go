package dd_sds

import (
	"fmt"
	"testing"
)

func TestValidateRegex(t *testing.T) {
	// Test valid regex
	valid, err := ValidateRegex("hello")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("valid:", valid)

	// Test invalid regex to ensure memory is properly freed
	valid, err = ValidateRegex("[")
	if err == nil {
		t.Fatal("Expected error for invalid regex")
	}
	fmt.Println("invalid regex error:", err)
}
