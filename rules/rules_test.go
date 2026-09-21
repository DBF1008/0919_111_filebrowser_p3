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

	globalLayers := func(globalRules, userRules []Rule) []Layer {
		return []Layer{
			{Name: "global", Rules: globalRules},
			{Name: "user", Rules: userRules},
		}
	}

	t.Run("no rules defaults to allow", func(t *testing.T) {
		t.Parallel()
		d := Evaluate("/anything", globalLayers(nil, nil)...)
		if !d.Allow || d.Matched {
			t.Errorf("got %+v; want allow=true, matched=false", d)
		}
	})

	t.Run("no matching rule defaults to allow", func(t *testing.T) {
		t.Parallel()
		d := Evaluate("/other", globalLayers(
			[]Rule{{Allow: false, Path: "/blocked"}},
			[]Rule{{Allow: false, Path: "/also-blocked"}},
		)...)
		if !d.Allow || d.Matched {
			t.Errorf("got %+v; want allow=true, matched=false", d)
		}
	})

	t.Run("global deny overrides user allow", func(t *testing.T) {
		t.Parallel()
		d := Evaluate("/secret/file.txt", globalLayers(
			[]Rule{{Allow: false, Path: "/secret"}},
			[]Rule{{Allow: true, Path: "/secret/file.txt"}},
		)...)
		if d.Allow || !d.Matched || d.Layer != "global" {
			t.Errorf("got %+v; want allow=false from global layer", d)
		}
		if d.Rule == nil || d.Rule.Path != "/secret" {
			t.Errorf("got rule %+v; want deciding rule /secret", d.Rule)
		}
	})

	t.Run("global allow overrides user deny", func(t *testing.T) {
		t.Parallel()
		d := Evaluate("/shared/file.txt", globalLayers(
			[]Rule{{Allow: true, Path: "/shared"}},
			[]Rule{{Allow: false, Path: "/shared/file.txt"}},
		)...)
		if !d.Allow || !d.Matched || d.Layer != "global" {
			t.Errorf("got %+v; want allow=true from global layer", d)
		}
	})

	t.Run("user rules decide when no global rule matches", func(t *testing.T) {
		t.Parallel()
		d := Evaluate("/private/doc.txt", globalLayers(
			[]Rule{{Allow: false, Path: "/unrelated"}},
			[]Rule{{Allow: false, Path: "/private"}},
		)...)
		if d.Allow || !d.Matched || d.Layer != "user" {
			t.Errorf("got %+v; want allow=false from user layer", d)
		}
	})

	t.Run("last matching rule wins within a layer", func(t *testing.T) {
		t.Parallel()
		d := Evaluate("/data/file.txt", globalLayers(
			[]Rule{
				{Allow: false, Path: "/data"},
				{Allow: true, Path: "/data/file.txt"},
			},
			nil,
		)...)
		if !d.Allow || !d.Matched || d.Layer != "global" {
			t.Errorf("got %+v; want allow=true from global layer", d)
		}
		if d.Rule == nil || d.Rule.Path != "/data/file.txt" {
			t.Errorf("got rule %+v; want deciding rule /data/file.txt", d.Rule)
		}
	})

	t.Run("regex rules participate in layers", func(t *testing.T) {
		t.Parallel()
		d := Evaluate("/tmp/secret.log", globalLayers(
			[]Rule{{Regex: true, Allow: false, Regexp: &Regexp{Raw: `\.log$`}}},
			[]Rule{{Allow: true, Path: "/tmp"}},
		)...)
		if d.Allow || !d.Matched || d.Layer != "global" {
			t.Errorf("got %+v; want allow=false from global layer", d)
		}
	})
}
