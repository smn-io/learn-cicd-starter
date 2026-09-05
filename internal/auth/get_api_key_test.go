package auth

import (
	"errors"
	"net/http"
	"testing"
)

func headerWith(key, value string) http.Header {
	h := http.Header{}
	h.Set(key, value)
	return h
}

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    bool
		wantErrIs  error
		wantErrMsg string
	}{
		{
			name:      "nil headers",
			headers:   nil,
			wantErr:   true,
			wantErrIs: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "no authorization header",
			headers:   http.Header{},
			wantErr:   true,
			wantErrIs: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "empty authorization header",
			headers:   http.Header{"Authorization": {""}},
			wantErr:   true,
			wantErrIs: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": {"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
		},
		{
			name:    "case insensitive header name",
			headers: headerWith("authorization", "ApiKey my-secret-key"),
			wantKey: "my-secret-key",
		},
		{
			name:    "extra whitespace separated parts are ignored",
			headers: http.Header{"Authorization": {"ApiKey my-secret-key trailing"}},
			wantKey: "my-secret-key",
		},
		{
			name:       "missing key after prefix",
			headers:    http.Header{"Authorization": {"ApiKey"}},
			wantErr:    true,
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "wrong scheme",
			headers:    http.Header{"Authorization": {"Bearer my-secret-key"}},
			wantErr:    true,
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "wrong scheme casing",
			headers:    http.Header{"Authorization": {"apikey my-secret-key"}},
			wantErr:    true,
			wantErrMsg: "malformed authorization header",
		},
		{
			name:    "empty key after prefix",
			headers: http.Header{"Authorization": {"ApiKey "}},
			wantKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("GetAPIKey() expected an error, got nil (key %q)", got)
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErrIs)
				}
				if tt.wantErrMsg != "" && err.Error() != tt.wantErrMsg {
					t.Errorf("GetAPIKey() error = %q, want %q", err.Error(), tt.wantErrMsg)
				}
				if got != "" {
					t.Errorf("GetAPIKey() key = %q, want empty string on error", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("GetAPIKey() unexpected error: %v", err)
			}
			if got != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", got, tt.wantKey)
			}
		})
	}
}
