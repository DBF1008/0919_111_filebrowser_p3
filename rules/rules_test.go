package rules

import "testing"

func TestRuleMatches(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		rulePath string
		testPath string
		want     bool
	}{
		{"exact match", "/uploads", "/uploads", true},
		{"child path", "/uploads", "/uploads/file.txt", true},
		{"sibling prefix", "/uploads", "/uploads_backup/secret.txt", false},
		{"root rule", "/", "/anything", true},
		{"trailing slash rule", "/uploads/", "/uploads/file.txt", true},
		{"trailing slash no sibling", "/uploads/", "/uploads_backup/file.txt", false},
		{"nested child", "/data/shared", "/data/shared/docs/file.txt", true},
		{"nested sibling", "/data/shared", "/data/shared_private/file.txt", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &Rule{Path: tc.rulePath}
			got := r.Matches(tc.testPath)
			if got != tc.want {
				t.Errorf("Rule{Path: %q}.Matches(%q) = %v; want %v", tc.rulePath, tc.testPath, got, tc.want)
			}
		})
	}
}

func TestMatchHidden(t *testing.T) {
	cases := map[string]bool{
		"/":                   false,
		"/src":                false,
		"/src/":               false,
		"/.circleci":          true,
		"/a/b/c/.docker.json": true,
		".docker.json":        true,
		"Dockerfile":          false,
		"/Dockerfile":         false,
	}

	for path, want := range cases {
		got := MatchHidden(path)
		if got != want {
			t.Errorf("MatchHidden(%s)=%v; want %v", path, got, want)
		}
	}
}

func TestEvaluate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		path   string
		layers [][]Rule
		want   bool
	}{
		{
			name: "no rules defaults to allow",
			path: "/anything",
			want: true,
		},
		{
			name: "single deny rule",
			path: "/secret/file.txt",
			layers: [][]Rule{
				{{Path: "/secret", Allow: false}},
			},
			want: false,
		},
		{
			name: "last match wins within a layer",
			path: "/data",
			layers: [][]Rule{
				{{Path: "/data", Allow: false}, {Path: "/data", Allow: true}},
			},
			want: true,
		},
		{
			name: "higher layer overrides lower layer",
			path: "/secret",
			layers: [][]Rule{
				{{Path: "/secret", Allow: true}},
				{{Path: "/secret", Allow: false}},
			},
			want: false,
		},
		{
			name: "lower layer decides when higher layer has no match",
			path: "/docs",
			layers: [][]Rule{
				{{Path: "/docs", Allow: false}},
				{{Path: "/other", Allow: true}},
			},
			want: false,
		},
		{
			name: "higher layer allow overrides lower layer deny",
			path: "/public",
			layers: [][]Rule{
				{{Path: "/public", Allow: false}},
				{{Path: "/public", Allow: true}},
			},
			want: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _ := Evaluate(tc.path, tc.layers...)
			if got != tc.want {
				t.Errorf("Evaluate(%q) = %v; want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestEvaluateRecordsMatches(t *testing.T) {
	t.Parallel()

	userRules := []Rule{{Path: "/a", Allow: true}}
	globalRules := []Rule{{Path: "/a", Allow: false}, {Path: "/a/b", Allow: true}}

	allow, matches := Evaluate("/a/b", userRules, globalRules)
	if !allow {
		t.Fatalf("Evaluate(/a/b) = false; want true")
	}
	if len(matches) != 3 {
		t.Fatalf("Evaluate recorded %d matches; want 3", len(matches))
	}

	wantLayers := []int{0, 1, 1}
	wantPaths := []string{"/a", "/a", "/a/b"}
	wantAllows := []bool{true, false, true}
	for i, m := range matches {
		if m.Layer != wantLayers[i] {
			t.Errorf("matches[%d].Layer = %d; want %d", i, m.Layer, wantLayers[i])
		}
		if m.Rule.Path != wantPaths[i] {
			t.Errorf("matches[%d].Rule.Path = %q; want %q", i, m.Rule.Path, wantPaths[i])
		}
		if m.Rule.Allow != wantAllows[i] {
			t.Errorf("matches[%d].Rule.Allow = %v; want %v", i, m.Rule.Allow, wantAllows[i])
		}
	}
}
