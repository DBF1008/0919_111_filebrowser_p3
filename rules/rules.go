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

// Layer is a named, prioritized group of rules. Layers are evaluated in
// the order they are passed to Evaluate: the first layer containing a
// matching rule decides the outcome, so layers listed earlier have
// strictly higher priority than later ones. Within a single layer the
// last matching rule wins.
type Layer struct {
	Name  string
	Rules []Rule
}

// Decision describes the outcome of evaluating a path against layered
// rule sets.
type Decision struct {
	Allow   bool   // Allow is the final verdict.
	Matched bool   // Matched reports whether any rule matched the path.
	Layer   string // Layer is the name of the layer that decided the outcome.
	Rule    *Rule  // Rule is the rule that decided the outcome (nil when none matched).
}

// Evaluate resolves the allow verdict for path against the given layers,
// in descending priority order. When no rule in any layer matches, the
// default is to allow.
func Evaluate(path string, layers ...Layer) Decision {
	for i := range layers {
		layer := &layers[i]

		var matched *Rule
		for j := range layer.Rules {
			if layer.Rules[j].Matches(path) {
				matched = &layer.Rules[j]
			}
		}

		if matched != nil {
			return Decision{
				Allow:   matched.Allow,
				Matched: true,
				Layer:   layer.Name,
				Rule:    matched,
			}
		}
	}

	return Decision{Allow: true}
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
