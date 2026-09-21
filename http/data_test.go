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

func newCheckData(userRules, globalRules []rules.Rule, checkerPrefix string) *data {
	return &data{
		settings:      &settings.Settings{Rules: globalRules},
		user:          &users.User{Rules: userRules},
		checkerPrefix: checkerPrefix,
	}
}

func TestCheckLayeredRulePriority(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		userRules   []rules.Rule
		globalRules []rules.Rule
		path        string
		want        bool
	}{
		"no rules defaults to allow": {
			path: "/anything",
			want: true,
		},
		"global deny overrides user allow": {
			userRules:   []rules.Rule{{Path: "/secret", Allow: true}},
			globalRules: []rules.Rule{{Path: "/secret", Allow: false}},
			path:        "/secret/file.txt",
			want:        false,
		},
		"global allow overrides user deny": {
			userRules:   []rules.Rule{{Path: "/public", Allow: false}},
			globalRules: []rules.Rule{{Path: "/public", Allow: true}},
			path:        "/public",
			want:        true,
		},
		"user deny applies when no global rule matches": {
			userRules:   []rules.Rule{{Path: "/private", Allow: false}},
			globalRules: []rules.Rule{{Path: "/other", Allow: false}},
			path:        "/private/doc.txt",
			want:        false,
		},
		"last match wins within the user layer": {
			userRules: []rules.Rule{
				{Path: "/data", Allow: false},
				{Path: "/data", Allow: true},
			},
			path: "/data",
			want: true,
		},
		"last match wins within the global layer": {
			globalRules: []rules.Rule{
				{Path: "/data", Allow: true},
				{Path: "/data", Allow: false},
			},
			path: "/data",
			want: false,
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := newCheckData(tc.userRules, tc.globalRules, "")
			if got := d.Check(tc.path); got != tc.want {
				t.Errorf("Check(%q) = %v; want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestCheckCheckerPrefixBoundary(t *testing.T) {
	t.Parallel()

	denySecret := []rules.Rule{{Path: "/secret", Allow: false}}
	denyShareSecret := []rules.Rule{{Path: "/share/secret", Allow: false}}

	testCases := map[string]struct {
		checkerPrefix string
		globalRules   []rules.Rule
		path          string
		want          bool
	}{
		"empty prefix leaves path untouched": {
			checkerPrefix: "",
			globalRules:   denySecret,
			path:          "/secret",
			want:          false,
		},
		"root prefix (share equals user scope) leaves path untouched": {
			checkerPrefix: "/",
			globalRules:   denySecret,
			path:          "/secret",
			want:          false,
		},
		"current-dir prefix leaves path untouched": {
			checkerPrefix: ".",
			globalRules:   denySecret,
			path:          "/secret",
			want:          false,
		},
		"share subdirectory prefix is joined": {
			checkerPrefix: "/share",
			globalRules:   denyShareSecret,
			path:          "/secret",
			want:          false,
		},
		"already resolved path is not prefixed twice": {
			checkerPrefix: "/share",
			globalRules:   denyShareSecret,
			path:          "/share/secret",
			want:          false,
		},
		"prefix itself is not duplicated": {
			checkerPrefix: "/share",
			globalRules:   []rules.Rule{{Path: "/share", Allow: false}},
			path:          "/share",
			want:          false,
		},
		"sibling directory with common prefix is not resolved": {
			checkerPrefix: "/share",
			globalRules:   []rules.Rule{{Path: "/share/share_other", Allow: false}},
			path:          "/share_other",
			want:          false,
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := newCheckData(nil, tc.globalRules, tc.checkerPrefix)
			if got := d.Check(tc.path); got != tc.want {
				t.Errorf("Check(%q) with prefix %q = %v; want %v",
					tc.path, tc.checkerPrefix, got, tc.want)
			}
		})
	}
}

func TestCheckHideDotfiles(t *testing.T) {
	t.Parallel()

	d := newCheckData(nil, nil, "")
	d.user.HideDotfiles = true

	if d.Check("/.hidden") {
		t.Errorf("Check(%q) = true; want false for hidden path", "/.hidden")
	}
	if !d.Check("/visible") {
		t.Errorf("Check(%q) = false; want true for visible path", "/visible")
	}
}

func TestCheckDebugLogging(t *testing.T) {
	var buf bytes.Buffer
	previousOutput := log.Writer()
	previousFlags := log.Flags()
	previousDebug := debugEnabled
	log.SetOutput(&buf)
	log.SetFlags(0)
	debugEnabled = true
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
		debugEnabled = previousDebug
	})

	d := newCheckData(
		[]rules.Rule{{Path: "/secret", Allow: true}},
		[]rules.Rule{{Path: "/secret", Allow: false}},
		"",
	)
	if d.Check("/secret/file.txt") {
		t.Fatalf("Check(%q) = true; want false", "/secret/file.txt")
	}

	out := buf.String()
	for _, want := range []string{
		`check "/secret/file.txt"`,
		`layer=user`,
		`layer=global`,
		`path="/secret"`,
		`allow=false`,
		"final decision allow=false",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("debug log missing %q; got:\n%s", want, out)
		}
	}
}
