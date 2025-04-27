package auth

import (
	"errors"
	"net/http"
	"testing"
)

// GetAPIKey -
func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		header  http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "no authorization header",
			header:  http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed authorization header",
			header: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer abc123")
				return h
			}(),
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "valid API key header",
			header: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey abc123")
				return h
			}(),
			wantKey: "abc123",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.header)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("expected error %q, got %q", tt.wantErr.Error(), err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if gotKey != tt.wantKey {
					t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
				}
			}
		})
	}
}
