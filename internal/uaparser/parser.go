package uaparser

import (
	"regexp"
	"strings"
)

// Result holds the parsed browser and OS names.
type Result struct {
	Browser string
	OS      string
}

var (
	chromeVersionRe  = regexp.MustCompile(`Chrome/(\d+)`)
	firefoxVersionRe = regexp.MustCompile(`Firefox/(\d+)`)
)

// Parse extracts browser and OS from a raw User-Agent string.
// Returns "Unknown" for unrecognised values rather than an error.
func Parse(ua string) Result {
	return Result{
		Browser: parseBrowser(ua),
		OS:      parseOS(ua),
	}
}

func parseOS(ua string) string {
	switch {
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		return "iOS"
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X"):
		return "macOS"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	default:
		return "Unknown"
	}
}

func parseBrowser(ua string) string {
	switch {
	case strings.Contains(ua, "Edg/"):
		return "Edge"
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera"):
		return "Opera"
	case strings.Contains(ua, "Firefox/"):
		if m := firefoxVersionRe.FindStringSubmatch(ua); len(m) > 1 {
			return "Firefox " + m[1]
		}
		return "Firefox"
	case strings.Contains(ua, "Chrome/"):
		if m := chromeVersionRe.FindStringSubmatch(ua); len(m) > 1 {
			return "Chrome " + m[1]
		}
		return "Chrome"
	case strings.Contains(ua, "Safari/"):
		return "Safari"
	default:
		return "Unknown"
	}
}
