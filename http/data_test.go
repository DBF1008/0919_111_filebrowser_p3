package fbhttp

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/filebrowser/filebrowser/v2/rules"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

func newTestData(globalRules, userRules []rules.Rule, checkerPrefix string) *data {
	return &data{
		settings:      &settings.Settings{Rules: globalRules},
		user:          &users.User{Rules: userRules},
		checkerPrefix: checkerPrefix,
	}
}

func TestDataCheckRulePriority(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		globalRules []rules.Rule
		userRules   []rules.Rule
		path        string
		want        bool
	}{
		"no rules allows": {
			path: "/anything",
			want: true,
		},
		"global deny is not overridden by user allow": {
			globalRules: []rules.Rule{{Allow: false, Path: "/forbidden"}},
			userRules:   []rules.Rule{{Allow: true, Path: "/forbidden"}},
			path:        "/forbidden/secret.txt",
			want:        false,
		},
		"user allow applies when no global rule matches": {
			globalRules: []rules.Rule{{Allow: false, Path: "/forbidden"}},
			userRules:   []rules.Rule{{Allow: false, Path: "/private"}},
			path:        "/public/file.txt",
			want:        true,
		},
		"user deny applies when no global rule matches": {
			globalRules: []rules.Rule{{Allow: false, Path: "/forbidden"}},
			userRules:   []rules.Rule{{Allow: false, Path: "/private"}},
			path:        "/private/doc.txt",
			want:        false,
		},
		"last matching user rule wins": {
			userRules: []rules.Rule{
				{Allow: false, Path: "/data"},
				{Allow: true, Path: "/data/public"},
			},
			path: "/data/public/readme.txt",
			want: true,
		},
		"last matching global rule wins": {
			globalRules: []rules.Rule{
				{Allow: true, Path: "/data"},
				{Allow: false, Path: "/data/secret"},
			},
			userRules: []rules.Rule{{Allow: true, Path: "/data/secret"}},
			path:      "/data/secret/key.pem",
			want:      false,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := newTestData(tc.globalRules, tc.userRules, "")
			if got := d.Check(tc.path); got != tc.want {
				t.Errorf("Check(%q) = %v; want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestDataCheckCheckerPrefix(t *testing.T) {
	t.Parallel()

	userRules := []rules.Rule{{Allow: false, Path: "/projects/private"}}

	testCases := map[string]struct {
		checkerPrefix string
		path          string
		want          bool
	}{
		"rebased path is resolved back to scope": {
			checkerPrefix: "/projects",
			path:          "/private/secret.txt",
			want:          false,
		},
		"rebased allowed path": {
			checkerPrefix: "/projects",
			path:          "/public/readme.txt",
			want:          true,
		},
		"share root equals scope root, slash prefix": {
			checkerPrefix: "/",
			path:          "/projects/private/secret.txt",
			want:          false,
		},
		"share root equals scope root, dot prefix": {
			checkerPrefix: ".",
			path:          "/projects/private/secret.txt",
			want:          false,
		},
		"no prefix": {
			checkerPrefix: "",
			path:          "/projects/private/secret.txt",
			want:          false,
		},
		"already prefixed path is not prefixed twice": {
			checkerPrefix: "/projects",
			path:          "/projects/private/secret.txt",
			want:          false,
		},
		"prefix itself is not duplicated": {
			checkerPrefix: "/projects",
			path:          "/projects",
			want:          true,
		},
		"sibling directory with shared prefix is not confused": {
			checkerPrefix: "/projects",
			path:          "/projects2/private/secret.txt",
			want:          true,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := newTestData(nil, userRules, tc.checkerPrefix)
			if got := d.Check(tc.path); got != tc.want {
				t.Errorf("Check(%q) with prefix %q = %v; want %v",
					tc.path, tc.checkerPrefix, got, tc.want)
			}
		})
	}
}

func TestDataCheckHideDotfiles(t *testing.T) {
	t.Parallel()

	d := newTestData(nil, nil, "")
	d.user.HideDotfiles = true

	if d.Check("/visible/.hidden") {
		t.Error("Check on hidden path = true; want false")
	}
	if !d.Check("/visible/file.txt") {
		t.Error("Check on visible path = false; want true")
	}
}

func TestDataCheckDebugLogging(t *testing.T) {
	defer func(prev bool) { rulesDebug = prev }(rulesDebug)
	rulesDebug = true

	var buf bytes.Buffer
	prevWriter := log.Writer()
	defer log.SetOutput(prevWriter)
	log.SetOutput(&buf)

	d := newTestData(
		[]rules.Rule{{Allow: false, Path: "/forbidden"}},
		nil,
		"",
	)
	if d.Check("/forbidden/file.txt") {
		t.Fatal("Check = true; want false")
	}

	out := buf.String()
	if !strings.Contains(out, "/forbidden") || !strings.Contains(out, "allow=false") {
		t.Errorf("debug log %q does not contain matched rule path and allow result", out)
	}
	if !strings.Contains(out, "global") {
		t.Errorf("debug log %q does not contain the deciding layer", out)
	}
}

func TestCheckerPrefixForBase(t *testing.T) {
	t.Parallel()

	testCases := map[string]string{
		"/":          "",
		".":          "",
		"":           "",
		"/projects":  "/projects",
		"/projects/": "/projects",
		"/a/b/c":     "/a/b/c",
	}

	for base, want := range testCases {
		if got := checkerPrefixForBase(base); got != want {
			t.Errorf("checkerPrefixForBase(%q) = %q; want %q", base, got, want)
		}
	}
}
