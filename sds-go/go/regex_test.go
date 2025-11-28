package dd_sds

import (
	"testing"
)

func TestValidateRegex(t *testing.T) {
	_, err := ValidateRegex("hello")
	if err != nil {
		t.Fatal(err)
	}

	_, err = ValidateRegex("[")
	if err == nil {
		t.Fatal("Expected error for invalid regex")
	}
}

func TestExplainRegex(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		valid   bool
	}{
		{
			name:    "simple literal",
			pattern: "hello",
			valid:   true,
		},
		{
			name:    "digit class",
			pattern: "\\d+",
			valid:   true,
		},
		{
			name:    "alternation",
			pattern: "a|b|c",
			valid:   true,
		},
		{
			name:    "capturing group",
			pattern: "(abc)",
			valid:   true,
		},
		{
			name:    "complex pattern",
			pattern: "(\\d{3})-\\d{3}-\\d{4}",
			valid:   true,
		},
		{
			name:    "invalid regex",
			pattern: "[",
			valid:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			explanation, err := ExplainRegex(tt.pattern)
			if err != nil {
				t.Fatalf("ExplainRegex() error = %v", err)
			}

			if explanation.IsValid != tt.valid {
				t.Errorf("ExplainRegex() IsValid = %v, want %v", explanation.IsValid, tt.valid)
			}

			if tt.valid {
				if explanation.Tree == nil {
					t.Error("ExplainRegex() Tree should not be nil for valid regex")
				}
				if explanation.Error != nil {
					t.Errorf("ExplainRegex() Error should be nil for valid regex, got %v", *explanation.Error)
				}

				if explanation.Tree.NodeType == "" {
					t.Error("ExplainRegex() Tree.NodeType should not be empty")
				}
				if explanation.Tree.Description == "" {
					t.Error("ExplainRegex() Tree.Description should not be empty")
				}
			} else {
				if explanation.Error == nil {
					t.Error("ExplainRegex() Error should not be nil for invalid regex")
				}
			}
		})
	}
}

func TestExplainRegexWithPositions(t *testing.T) {
	explanation, err := ExplainRegex("abc")
	if err != nil {
		t.Fatalf("ExplainRegex() error = %v", err)
	}

	if !explanation.IsValid {
		t.Fatal("ExplainRegex() should be valid")
	}

	if explanation.Tree == nil {
		t.Fatal("ExplainRegex() Tree should not be nil")
	}

	if explanation.Tree.Start < 0 {
		t.Errorf("ExplainRegex() Tree.Start should be >= 0, got %d", explanation.Tree.Start)
	}
	if explanation.Tree.End <= explanation.Tree.Start {
		t.Errorf("ExplainRegex() Tree.End (%d) should be > Start (%d)", explanation.Tree.End, explanation.Tree.Start)
	}
}

func TestExplainRegexWithChildren(t *testing.T) {
	explanation, err := ExplainRegex("a|b|c")
	if err != nil {
		t.Fatalf("ExplainRegex() error = %v", err)
	}

	if !explanation.IsValid {
		t.Fatal("ExplainRegex() should be valid")
	}

	if explanation.Tree == nil {
		t.Fatal("ExplainRegex() Tree should not be nil")
	}

	if explanation.Tree.NodeType != "Alternation" {
		t.Errorf("ExplainRegex() Tree.NodeType should be 'Alternation', got %s", explanation.Tree.NodeType)
	}

	if len(explanation.Tree.Children) != 3 {
		t.Errorf("ExplainRegex() Tree.Children should have 3 elements, got %d", len(explanation.Tree.Children))
	}
}
