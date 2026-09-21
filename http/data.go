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

// debugEnabled toggles debug-level logging for rule evaluation. It is a
// package-level variable so tests (or an embedding binary) can flip it
// without recompiling.
var debugEnabled = os.Getenv("FB_DEBUG") != ""

func debugf(format string, args ...interface{}) {
	if debugEnabled {
		log.Printf("DEBUG: "+format, args...)
	}
}

// Check implements rules.Checker.
func (d *data) Check(path string) bool {
	path = d.resolveCheckPath(path)

	if d.user.HideDotfiles && rules.MatchHidden(path) {
		debugf("check %q: denied, path is hidden", path)
		return false
	}

	// Layered evaluation with explicit priority: user rules form the
	// low-priority layer, global (settings) rules the high-priority layer.
	// A matching global rule therefore always overrides user rules, so an
	// administrator's deny rule can never be re-allowed by a user rule.
	allow, matches := rules.Evaluate(path, d.user.Rules, d.settings.Rules)
	for _, m := range matches {
		layer := "user"
		if m.Layer > 0 {
			layer = "global"
		}
		debugf("check %q: rule hit layer=%s path=%q regex=%v allow=%v",
			path, layer, m.Rule.Path, m.Rule.Regex, m.Rule.Allow)
	}
	debugf("check %q: final decision allow=%v", path, allow)
	return allow
}

// resolveCheckPath maps a path relative to the (possibly rebased)
// filesystem back to the user's original scope, so that rules — which are
// scope-relative — are matched against the real path.
func (d *data) resolveCheckPath(path string) string {
	prefix := d.checkerPrefix
	// An empty, root, or current-dir prefix means the filesystem was not
	// really rebased (e.g. a share rooted exactly at the user's scope).
	// The incoming path is already scope-relative and must be left alone,
	// otherwise joining the prefix would corrupt it.
	if prefix == "" || prefix == "/" || prefix == "." {
		return path
	}
	// The path is already resolved against the user's scope; joining the
	// prefix again would duplicate it and break rule matching.
	if path == prefix || strings.HasPrefix(path, prefix+"/") {
		return path
	}
	return gopath.Join(prefix, path)
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
