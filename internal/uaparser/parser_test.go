package uaparser_test

import (
	"testing"

	"central-auth/internal/uaparser"
)

func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		name        string
		ua          string
		wantBrowser string
		wantOS      string
	}{
		{
			name:        "Chrome on macOS",
			ua:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
			wantBrowser: "Chrome 149",
			wantOS:      "macOS",
		},
		{
			name:        "Safari on iOS",
			ua:          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			wantBrowser: "Safari",
			wantOS:      "iOS",
		},
		{
			name:        "Firefox on Windows",
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			wantBrowser: "Firefox 120",
			wantOS:      "Windows",
		},
		{
			name:        "Edge on Windows",
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			wantBrowser: "Edge",
			wantOS:      "Windows",
		},
		{
			name:        "Chrome on Android",
			ua:          "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
			wantBrowser: "Chrome 116",
			wantOS:      "Android",
		},
		{
			name:        "empty UA",
			ua:          "",
			wantBrowser: "Unknown",
			wantOS:      "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uaparser.Parse(tt.ua)
			if got.Browser != tt.wantBrowser {
				t.Errorf("browser = %q, want %q", got.Browser, tt.wantBrowser)
			}
			if got.OS != tt.wantOS {
				t.Errorf("os = %q, want %q", got.OS, tt.wantOS)
			}
		})
	}
}
