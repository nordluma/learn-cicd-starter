package auth

import (
	"net/http"
	"testing"
)

func TestReturnsApiKeyFromValidHeader(t *testing.T) {
	testCases := []struct {
		input http.Header
		want  string
	}{
		{input: http.Header{"Authorization": {"ApiKey one"}}, want: "one"},
		{input: http.Header{"Authorization": {"ApiKey two"}}, want: "two"},
		{
			input: http.Header{"Authorization": {"ApiKey three"}},
			want:  "three",
		},
	}

	for _, tc := range testCases {
		got, _ := GetAPIKey(tc.input)
		if got != tc.want {
			t.Errorf("expected: %s - got: %s", tc.want, got)
		}
	}
}

func TestInvalidAuthHeaders(t *testing.T) {
	malformedHeaderErr := "malformed authorization header"

	testCases := []struct {
		input http.Header
		want  string
	}{
		{
			input: http.Header{"Authorization": {"Give me the API"}},
			want:  malformedHeaderErr,
		},
		{
			input: http.Header{"Authorization": {"bearer thisIsAToken"}},
			want:  malformedHeaderErr,
		},
		{
			input: http.Header{"Authorization": {"yo"}},
			want:  malformedHeaderErr,
		},
		{
			input: http.Header{"X-Api-Key": {"yo"}},
			want:  ErrNoAuthHeaderIncluded.Error(),
		},
		{
			input: http.Header{"Content-Type": {"application/json"}},
			want:  ErrNoAuthHeaderIncluded.Error(),
		},
		{
			input: http.Header{},
			want:  ErrNoAuthHeaderIncluded.Error(),
		},
	}

	for _, tc := range testCases {
		_, err := GetAPIKey(tc.input)
		if err.Error() != tc.want {
			t.Errorf("expected error: %s - got: %s", tc.want, err)
		}
	}
}
