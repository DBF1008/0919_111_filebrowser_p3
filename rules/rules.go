package rules

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Checker is a Rules checker.
type Checker interface {
	Check(path string) bool
}

// Match describes a single rule hit recorded during Evaluate. It carries
// enough context for callers to log or audit how a decision was reached.
type Match struct {
	// Layer is the index of the layer the rule belongs to, following the
	// order in which the layers were passed to Evaluate.
	Layer int
	// Rule is the rule that matched the path.
	Rule *Rule
}

// Evaluate resolves the allow decision for path using a layered,
// last-match-wins policy. Layers are passed from the lowest to the highest
// priority: within a layer the last matching rule wins, and a layer with at
// least one match overrides every lower-priority layer. When no rule
// matches at all, the default decision is allow. Every rule hit is
// returned in evaluation order so callers can trace the decision.
func Evaluate(path string, layers ...[]Rule) (allow bool, matches []Match) {
	allow = true
	for layer, rules := range layers {
		for i := range rules {
			if rules[i].Matches(path) {
				allow = rules[i].Allow
				matches = append(matches, Match{Layer: layer, Rule: &rules[i]})
			}
		}
	}
	return allow, matches
}

// Rule is a allow/disallow rule.
type Rule struct {
	Regex  bool    `json:"regex"`
	Allow  bool    `json:"allow"`
	Path   string  `json:"path"`
	Regexp *Regexp `json:"regexp"`
}

// MatchHidden matches paths with a basename
// that begins with a dot.
func MatchHidden(path string) bool {
	return path != "" && strings.HasPrefix(filepath.Base(path), ".")
}

// Matches matches a path against a rule.
func (r *Rule) Matches(path string) bool {
	if r.Regex {
		return r.Regexp.MatchString(path)
	}

	if path == r.Path {
		return true
	}

	prefix := r.Path
	if prefix != "/" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	return strings.HasPrefix(path, prefix)
}

// Regexp is a wrapper to the native regexp type where we
// save the raw expression.
type Regexp struct {
	Raw    string `json:"raw"`
	regexp *regexp.Regexp
}

// MatchString checks if a string matches the regexp.
func (r *Regexp) MatchString(s string) bool {
	if r.regexp == nil {
		r.regexp = regexp.MustCompile(r.Raw)
	}

	return r.regexp.MatchString(s)
}
