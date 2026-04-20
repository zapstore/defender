package client

import (
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		isValid  bool
	}{
		{
			name:     "valid http URL",
			input:    "http://example.com",
			expected: "http://example.com",
			isValid:  true,
		},
		{
			name:     "valid https URL",
			input:    "https://example.com",
			expected: "https://example.com",
			isValid:  true,
		},
		{
			name:     "valid URL with path",
			input:    "https://example.com/api/v1",
			expected: "https://example.com/api/v1",
			isValid:  true,
		},
		{
			name:     "trailing slash is stripped",
			input:    "https://example.com/api/",
			expected: "https://example.com/api",
			isValid:  true,
		},
		{
			name:     "valid URL with port",
			input:    "http://localhost:8080",
			expected: "http://localhost:8080",
			isValid:  true,
		},
		{
			name:     "host:port without scheme gets http prepended",
			input:    "localhost:8080",
			expected: "http://localhost:8080",
			isValid:  true,
		},
		{
			name:     "bare hostname without scheme gets http prepended",
			input:    "example.com",
			expected: "http://example.com",
			isValid:  true,
		},
		{
			name:     "hostname with path without scheme gets http prepended",
			input:    "example.com/api/v1",
			expected: "http://example.com/api/v1",
			isValid:  true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
			isValid:  false,
		},
		{
			name:     "protocol-relative URL has no host after prepend",
			input:    "//example.com",
			expected: "",
			isValid:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := normalizeURL(test.input)
			if test.isValid && err != nil {
				t.Errorf("expected valid URL, got error: %v", err)
			}
			if !test.isValid && err == nil {
				t.Errorf("expected error for input %q, got nil", test.input)
			}
			if result != test.expected {
				t.Errorf("expected %q, got %q", test.expected, result)
			}
		})
	}
}
