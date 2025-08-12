package main

import (
	"fmt"
	"log"

	sds "github.com/DataDog/dd-sensitive-data-scanner/sds-go/go"
)

func main() {
	// Create a simple scanner without explicitly enabling return_matches
	rules := []sds.RuleConfig{
		sds.NewMatchingRule("test_rule", "password\\s*=\\s*['\"]([^'\"]+)['\"]", sds.ExtraConfig{}),
	}

	scanner, err := sds.CreateScanner(rules)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}

	testEvent := []byte(`{"login": "password = 'secret123'"}`)

	// Test default scan (validation=false)
	fmt.Println("=== Testing default scan (validation=false) ===")
	result1, err := scanner.Scan(testEvent)
	if err != nil {
		log.Fatalf("Default scan failed: %v", err)
	}
	fmt.Printf("Default scan result: %+v\n", result1)

	// Test scan with validation enabled (should work without configuration errors)
	fmt.Println("\n=== Testing scan with validation=true ===")
	result2, err := scanner.ScanWithValidation(testEvent, true)
	if err != nil {
		log.Fatalf("Validation scan failed: %v", err)
	}
	fmt.Printf("Validation scan result: %+v\n", result2)

	fmt.Println("\n✅ Both scans completed successfully! Validation can now be used without configuration errors.")
}
