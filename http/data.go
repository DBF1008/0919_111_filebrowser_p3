package fbhttp

import (
	"log"
	"net/http"
	"os"
	gopath "path"
	"strconv"
	"strings"

	"github.com/tomasen/realip"

	"github.com/filebrowser/filebrowser/v2/rules"
	"github.com/filebrowser/filebrowser/v2/runner"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage"
	"github.com/filebrowser/filebrowser/v2/users"
)

type handleFunc func(w http.ResponseWriter, r *http.Request, d *data) (int, error)

type data struct {
	*runner.Runner
	settings *settings.Settings
	server   *settings.Server
	store    *storage.Storage
	user     *users.User
	raw      interface{}

	// checkerPrefix is prepended to every path before evaluating rules. It is
	// set when the user's filesystem has been rebased onto a subdirectory (as
	// done for public shares), so that rules — which are relative to the user's
	// original scope — are still matched against the real path instead of the
	// rebased one. Empty for regular requests.
	checkerPrefix string
}

// Rule layer names, in descending priority order. Global (administrator)
// rules form the highest-priority layer, so a global deny can never be
// overridden by a user's own rules.
const (
	ruleLayerGlobal = "global"
	ruleLayerUser   = "user"
)

// rulesDebug enables debug-level logging of rule evaluation. It is
// enabled by setting the FILEBROWSER_RULES_DEBUG environment variable,
// which allows troubleshooting permission issues in production without
// rebuilding.
var rulesDebug = os.Getenv("FILEBROWSER_RULES_DEBUG") != ""

func rulesDebugf(format string, args ...interface{}) {
	if !rulesDebug {
		return
	}
	log.Printf("DEBUG: rules: "+format, args...)
}

// Check implements rules.Checker.
func (d *data) Check(path string) bool {
	path = d.resolveCheckPath(path)

	if d.user.HideDotfiles && rules.MatchHidden(path) {
		rulesDebugf("path=%q is a hidden dotfile -> allow=false", path)
		return false
	}

	decision := rules.Evaluate(path,
		rules.Layer{Name: ruleLayerGlobal, Rules: d.settings.Rules},
		rules.Layer{Name: ruleLayerUser, Rules: d.user.Rules},
	)

	if decision.Matched {
		rulesDebugf("path=%q matched rule %q in %q layer -> allow=%t",
			path, decision.Rule.Path, decision.Layer, decision.Allow)
	} else {
		rulesDebugf("path=%q matched no rule -> allow=%t (default)", path, decision.Allow)
	}

	return decision.Allow
}

// resolveCheckPath maps a path that is relative to a rebased filesystem
// root (see checkerPrefix) back to the user's original scope, so that
// rules — which are relative to the scope — keep matching.
func (d *data) resolveCheckPath(path string) string {
	prefix := d.checkerPrefix
	if prefix == "" || prefix == "/" || prefix == "." {
		// No rebasing in effect, or the filesystem was rebased onto the
		// scope root itself (e.g. a share of the user's whole scope): the
		// path is already relative to the scope.
		return path
	}

	// Never prepend the prefix twice: a path that already starts with the
	// prefix is already scope-relative.
	if path == prefix || strings.HasPrefix(path, prefix+"/") {
		return path
	}

	return gopath.Join(prefix, path)
}

// checkerPrefixForBase normalizes a share base path into a checker
// prefix. When the share root is the user's scope root itself (the base
// path cleans to "/" or "."), no prefix is needed: checked paths are
// already relative to the scope, and prefixing them would duplicate the
// scope root and break rule matching.
func checkerPrefixForBase(basePath string) string {
	cleaned := gopath.Clean(basePath)
	if cleaned == "/" || cleaned == "." {
		return ""
	}
	return cleaned
}

func handle(fn handleFunc, prefix string, store *storage.Storage, server *settings.Server) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range globalHeaders {
			w.Header().Set(k, v)
		}

		settings, err := store.Settings.Get()
		if err != nil {
			log.Fatalf("ERROR: couldn't get settings: %v\n", err)
			return
		}

		status, err := fn(w, r, &data{
			Runner:   &runner.Runner{Enabled: server.EnableExec, Settings: settings},
			store:    store,
			settings: settings,
			server:   server,
		})

		if status >= 400 || err != nil {
			clientIP := realip.FromRequest(r)
			log.Printf("%s: %v %s %v", r.URL.Path, status, clientIP, err)
		}

		if status != 0 {
			txt := http.StatusText(status)
			if status == http.StatusBadRequest && err != nil {
				txt += " (" + err.Error() + ")"
			}
			http.Error(w, strconv.Itoa(status)+" "+txt, status)
			return
		}
	})

	return stripPrefix(prefix, handler)
}
