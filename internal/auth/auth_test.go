package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey mysecretapikey"},
			},
			expectedKey:   "mysecretapikey",
			expectedError: nil,
		},
		{
			name: "No Authorization Header",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - Missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer someotherkey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Too few parts",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Empty key",
			headers: http.Header{
				"Authorization": []string{
					"ApiKey ",
				},
			},
			expectedKey:   "",
			expectedError: nil,
		},
		{
			name: "Authorization Header with extra spaces",
			headers: http.Header{
				"Authorization": []string{
					"ApiKey  anotherkey",
				},
			},
			expectedKey:   "",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			if apiKey != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, apiKey)
			}

			if !((err == nil && tt.expectedError == nil) ||
				(err != nil && tt.expectedError != nil && err.Error() == tt.expectedError.Error())) {
				t.Errorf("expected error %q, got %q", tt.expectedError, err)
			}
		})
	}
}
