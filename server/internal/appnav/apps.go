// Package appnav validates ClosedDoor's grant-filtered application links.
package appnav

import (
	"encoding/json"
	"net/url"
	"strings"
	"unicode"
)

type App struct {
	ID        string `json:"client_id"`
	Name      string `json:"name"`
	LaunchURL string `json:"launch_url,omitempty"`
}

func Clean(in []App, own string) []App {
	out := make([]App, 0)
	seen := map[string]bool{}
	for i, a := range in {
		if i >= 200 {
			break
		}
		if a.ID == "" || len(a.ID) > 200 || a.ID == own || seen[a.ID] || a.Name == "" || len(a.Name) > 200 || len(a.LaunchURL) > 2048 {
			continue
		}
		if strings.ContainsAny(a.LaunchURL, "\\") || strings.IndexFunc(a.ID+a.Name+a.LaunchURL, unicode.IsControl) >= 0 {
			continue
		}
		u, e := url.Parse(a.LaunchURL)
		if e != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Scheme != "https" {
			continue
		}
		seen[a.ID] = true
		out = append(out, a)
	}
	return out
}
func Encode(in []App) string { b, _ := json.Marshal(Clean(in, "")); return string(b) }
func Decode(raw string) []App {
	var a []App
	if len(raw) > 1<<20 || json.Unmarshal([]byte(raw), &a) != nil {
		return nil
	}
	return Clean(a, "")
}
