// Vendored from OmniCore reference/go/omniconnect; change upstream, not here.

package omniconnect

// ProtocolVersion is the wire version of the OmniCore integration protocol (docs/integration.md).
const ProtocolVersion = 1

// Size is a widget size in grid cells (the dashboard is 12 columns wide, one row is 80 px).
type Size struct {
	W int `json:"w"`
	H int `json:"h"`
}

type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// ConfigField describes one setting of a widget; its value reaches the provider as query parameter cfg.<key>.
type ConfigField struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"` // text | number | select | bool
	Options  []Option `json:"options,omitempty"`
	Default  string   `json:"default,omitempty"`
	Help     string   `json:"help,omitempty"`
	Required bool     `json:"required,omitempty"`
	// Dynamic: options are fetched from GET /options/{widget}/{key} (type select only).
	Dynamic bool `json:"dynamic,omitempty"`
}

type WidgetSpec struct {
	ID             string        `json:"id"`
	Title          string        `json:"title"`
	Description    string        `json:"description,omitempty"`
	Kind           string        `json:"kind"` // the payload kind normally returned (used for the gallery preview)
	Default        Size          `json:"default"`
	Min            *Size         `json:"min,omitempty"`
	Max            *Size         `json:"max,omitempty"`
	RefreshSeconds int           `json:"refresh_seconds,omitempty"` // default 60
	Config         []ConfigField `json:"config,omitempty"`
	// Roles limits the widget to people whose role in the app is listed (empty: everyone the app lets in).
	Roles []string `json:"roles,omitempty"`
}

type AppInfo struct {
	ID          string `json:"id"` // lower-case slug, [a-z][a-z0-9-]{1,30}; also the Beacon notification source id
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Version     string `json:"version,omitempty"`
	Icon        string `json:"icon,omitempty"` // one of OmniCore's icon names
	Accent      string `json:"accent,omitempty"`
	PublicURL   string `json:"public_url"`         // where people open the app in a browser
	OpenURL     string `json:"open_url,omitempty"` // path appended to PublicURL by "Open <app>"
}

type OverviewItem struct {
	Widget string            `json:"widget"`
	W      int               `json:"w"`
	H      int               `json:"h"`
	Config map[string]string `json:"config,omitempty"`
}

type Overview struct {
	Title   string         `json:"title,omitempty"`
	Widgets []OverviewItem `json:"widgets"`
}

// Category is one kind of notification an app can send. Level is its usual severity
// (info | notice | important | critical); Mandatory categories cannot be turned off by people.
type Category struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Level       string `json:"level"`
	Mandatory   bool   `json:"mandatory,omitempty"`
}

type Notifications struct {
	Categories []Category `json:"categories"`
}

type Manifest struct {
	Protocol      int           `json:"protocol"`
	App           AppInfo       `json:"app"`
	Widgets       []WidgetSpec  `json:"widgets"`
	Overview      Overview      `json:"overview"`
	Notifications Notifications `json:"notifications"`
	// Capabilities: "search" (GET /search), "options" (dynamic select options).
	Capabilities []string `json:"capabilities,omitempty"`
}

// SearchResult is one hit of the optional GET /search?q=... endpoint.
type SearchResult struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	Icon     string `json:"icon,omitempty"`
	Link     string `json:"link"`
}
