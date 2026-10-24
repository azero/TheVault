// Vendored from OmniCore reference/go/omniconnect; change upstream, not here.

package omniconnect

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Tone colours a value. Clients map it to their palette; unknown tones render as "muted".
type Tone string

const (
	ToneOK    Tone = "ok"
	ToneInfo  Tone = "info"
	ToneWarn  Tone = "warn"
	ToneBad   Tone = "bad"
	ToneMuted Tone = "muted"
)

// Widget kinds. A payload's Kind decides which other fields are read.
const (
	KindStat     = "stat"
	KindList     = "list"
	KindTable    = "table"
	KindSeries   = "series"
	KindProgress = "progress"
	KindStatus   = "status"
	KindAgenda   = "agenda"
	KindText     = "text"
	KindNotice   = "notice"
	KindError    = "error" // produced by OmniCore itself when a provider fails; providers never send it
)

// Widget is the one payload shape every provider returns; only the fields of its Kind are used.
// Every string is plain text: clients render it with textContent, never as markup.
type Widget struct {
	Kind      string `json:"kind"`
	Title     string `json:"title,omitempty"`
	Subtitle  string `json:"subtitle,omitempty"`
	Link      string `json:"link,omitempty"` // "/path" (inside the app) or http(s) URL
	Tone      Tone   `json:"tone,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"` // unix seconds

	// stat
	Value string    `json:"value,omitempty"`
	Unit  string    `json:"unit,omitempty"`
	Delta *Delta    `json:"delta,omitempty"`
	Spark []float64 `json:"spark,omitempty"`
	Stats []Stat    `json:"stats,omitempty"`

	// list
	Items []Item `json:"items,omitempty"`
	Empty string `json:"empty,omitempty"` // shown when there are no items/rows/events

	// table
	Columns []Column `json:"columns,omitempty"`
	Rows    []Row    `json:"rows,omitempty"`

	// series
	Chart  string   `json:"chart,omitempty"` // line | bar | area
	X      string   `json:"x,omitempty"`     // time | category
	Series []Series `json:"series,omitempty"`

	// progress
	Fraction *float64  `json:"fraction,omitempty"` // 0..1
	Label    string    `json:"label,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Segments []Segment `json:"segments,omitempty"`

	// status
	Checks []Check `json:"checks,omitempty"`

	// agenda
	Days []Day `json:"days,omitempty"`

	// text, notice
	Text   string  `json:"text,omitempty"`
	Action *Action `json:"action,omitempty"`
}

type Delta struct {
	Text string `json:"text"`
	Tone Tone   `json:"tone,omitempty"`
}
type Stat struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Tone  Tone   `json:"tone,omitempty"`
}
type Item struct {
	ID       string `json:"id,omitempty"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	Meta     string `json:"meta,omitempty"`
	Tone     Tone   `json:"tone,omitempty"`
	Icon     string `json:"icon,omitempty"`
	Badge    string `json:"badge,omitempty"`
	Link     string `json:"link,omitempty"`
	// Done is set for checkable items (native modules only; remote items are read-only).
	Done *bool `json:"done,omitempty"`
}
type Column struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Align string `json:"align,omitempty"` // left | right | center
}
type Row struct {
	Cells []string `json:"cells"`
	Link  string   `json:"link,omitempty"`
	Tone  Tone     `json:"tone,omitempty"`
}
type Segment struct {
	Label    string  `json:"label"`
	Fraction float64 `json:"fraction"`
	Tone     Tone    `json:"tone,omitempty"`
}
type Check struct {
	Label  string `json:"label"`
	State  string `json:"state"` // ok | warn | bad | unknown
	Detail string `json:"detail,omitempty"`
	Link   string `json:"link,omitempty"`
}
type Day struct {
	Date   string  `json:"date"` // YYYY-MM-DD
	Events []Event `json:"events"`
}
type Event struct {
	ID       string `json:"id,omitempty"`
	Title    string `json:"title"`
	Start    string `json:"start"`         // RFC 3339, or YYYY-MM-DD when AllDay
	End      string `json:"end,omitempty"` // same format
	AllDay   bool   `json:"all_day,omitempty"`
	Location string `json:"location,omitempty"`
	Color    string `json:"color,omitempty"` // #rrggbb
	Link     string `json:"link,omitempty"`
}
type Action struct {
	Label string `json:"label"`
	Link  string `json:"link"`
}

// Series is a named list of points. For x=time a point is [unix seconds, value]; for x=category it is [label, value].
type Series struct {
	Name   string  `json:"name"`
	Points []Point `json:"points"`
}
type Point struct {
	T     int64  // x=time
	Label string // x=category
	V     float64
	Cat   bool // true: Label is the x value
}

func (p Point) MarshalJSON() ([]byte, error) {
	if p.Cat {
		return json.Marshal([]any{p.Label, p.V})
	}
	return json.Marshal([]any{p.T, p.V})
}

func (p *Point) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil || len(raw) != 2 {
		return errors.New("a point is [x, value]")
	}
	if err := json.Unmarshal(raw[1], &p.V); err != nil {
		return errors.New("point value must be a number")
	}
	var s string
	if json.Unmarshal(raw[0], &s) == nil {
		p.Cat, p.Label = true, s
		return nil
	}
	return json.Unmarshal(raw[0], &p.T)
}

// Limits applied by Sanitize (and therefore by OmniCore to everything a remote app sends).
const (
	MaxItems   = 50
	MaxSeries  = 8
	MaxPoints  = 300
	MaxSpark   = 60
	MaxStats   = 6
	MaxChecks  = 50
	MaxDays    = 31
	MaxEvents  = 100
	MaxString  = 400
	MaxText    = 2000
	MaxColumns = 12
)

var kinds = map[string]bool{KindStat: true, KindList: true, KindTable: true, KindSeries: true, KindProgress: true,
	KindStatus: true, KindAgenda: true, KindText: true, KindNotice: true}

var tones = map[Tone]bool{ToneOK: true, ToneInfo: true, ToneWarn: true, ToneBad: true, ToneMuted: true}

// Sanitize returns a copy of w that is safe to hand to a renderer: unknown kinds are an error; strings are
// trimmed to length and stripped of control characters; unknown tones are dropped; links must be "/path" or
// http(s); collections are capped. It never panics on hostile input.
func Sanitize(w Widget) (Widget, error) {
	if !kinds[w.Kind] {
		return Widget{}, fmt.Errorf("unknown widget kind %q", w.Kind)
	}
	s := func(v string) string { return clean(v, MaxString) }
	t := func(v Tone) Tone {
		if tones[v] {
			return v
		}
		return ""
	}
	out := Widget{Kind: w.Kind, Title: s(w.Title), Subtitle: s(w.Subtitle), Link: link(w.Link), Tone: t(w.Tone), UpdatedAt: w.UpdatedAt,
		Value: clean(w.Value, 40), Unit: clean(w.Unit, 20), Empty: s(w.Empty), Chart: oneOf(w.Chart, "line", "bar", "area"),
		X: oneOf(w.X, "time", "category"), Label: s(w.Label), Detail: s(w.Detail), Text: clean(w.Text, MaxText)}
	if w.Delta != nil {
		out.Delta = &Delta{Text: s(w.Delta.Text), Tone: t(w.Delta.Tone)}
	}
	for i, v := range w.Spark {
		if i >= MaxSpark {
			break
		}
		out.Spark = append(out.Spark, finite(v))
	}
	for i, v := range w.Stats {
		if i >= MaxStats {
			break
		}
		out.Stats = append(out.Stats, Stat{Label: s(v.Label), Value: clean(v.Value, 40), Tone: t(v.Tone)})
	}
	for i, v := range w.Items {
		if i >= MaxItems {
			break
		}
		out.Items = append(out.Items, Item{ID: clean(v.ID, 80), Title: s(v.Title), Subtitle: s(v.Subtitle), Meta: s(v.Meta), Tone: t(v.Tone),
			Icon: clean(v.Icon, 30), Badge: clean(v.Badge, 30), Link: link(v.Link), Done: v.Done})
	}
	for i, v := range w.Columns {
		if i >= MaxColumns {
			break
		}
		out.Columns = append(out.Columns, Column{Key: clean(v.Key, 40), Label: s(v.Label), Align: oneOf(v.Align, "left", "right", "center")})
	}
	for i, v := range w.Rows {
		if i >= MaxItems {
			break
		}
		r := Row{Link: link(v.Link), Tone: t(v.Tone)}
		for j, c := range v.Cells {
			if j >= MaxColumns {
				break
			}
			r.Cells = append(r.Cells, s(c))
		}
		out.Rows = append(out.Rows, r)
	}
	for i, v := range w.Series {
		if i >= MaxSeries {
			break
		}
		ns := Series{Name: s(v.Name)}
		for j, p := range v.Points {
			if j >= MaxPoints {
				break
			}
			ns.Points = append(ns.Points, Point{T: p.T, Label: s(p.Label), V: finite(p.V), Cat: p.Cat})
		}
		out.Series = append(out.Series, ns)
	}
	if w.Fraction != nil {
		f := clamp01(finite(*w.Fraction))
		out.Fraction = &f
	}
	for i, v := range w.Segments {
		if i >= MaxStats {
			break
		}
		out.Segments = append(out.Segments, Segment{Label: s(v.Label), Fraction: clamp01(finite(v.Fraction)), Tone: t(v.Tone)})
	}
	for i, v := range w.Checks {
		if i >= MaxChecks {
			break
		}
		out.Checks = append(out.Checks, Check{Label: s(v.Label), State: oneOf(v.State, "ok", "warn", "bad", "unknown"), Detail: s(v.Detail), Link: link(v.Link)})
	}
	for i, d := range w.Days {
		if i >= MaxDays {
			break
		}
		nd := Day{Date: clean(d.Date, 10)}
		for j, e := range d.Events {
			if j >= MaxEvents {
				break
			}
			nd.Events = append(nd.Events, Event{ID: clean(e.ID, 80), Title: s(e.Title), Start: clean(e.Start, 40), End: clean(e.End, 40),
				AllDay: e.AllDay, Location: s(e.Location), Color: color(e.Color), Link: link(e.Link)})
		}
		out.Days = append(out.Days, nd)
	}
	if w.Action != nil {
		if l := link(w.Action.Link); l != "" {
			out.Action = &Action{Label: s(w.Action.Label), Link: l}
		}
	}
	return out, nil
}

func clean(v string, max int) string {
	v = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToValidUTF8(v, ""))
	v = strings.TrimSpace(v)
	if utf8.RuneCountInString(v) > max {
		v = string([]rune(v)[:max])
	}
	return v
}

func link(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 2000 {
		return ""
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return ""
		}
	}
	if strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") {
		return v
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return ""
	}
	return v
}

func color(v string) string {
	if len(v) == 7 && v[0] == '#' {
		for _, r := range v[1:] {
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
				return ""
			}
		}
		return v
	}
	return ""
}

func oneOf(v string, allowed ...string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return ""
}

func finite(f float64) float64 {
	if f != f || f > 1e15 || f < -1e15 {
		return 0
	}
	return f
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}
