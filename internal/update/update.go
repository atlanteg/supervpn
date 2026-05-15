package update

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	releasesRepo = "atlanteg/supervpn-releases"
	apiURL       = "https://api.github.com/repos/" + releasesRepo + "/releases/latest"
	downloadBase = "https://github.com/" + releasesRepo + "/releases/latest/download/"
)

// CheckAndUpdate checks for a newer release. If found, downloads the asset,
// replaces the running binary, and re-execs. Does not return on success.
// Any error is logged and the caller continues with the current version.
func CheckAndUpdate(currentVersion, asset string) {
	cur, err := parseVersion(currentVersion)
	if err != nil {
		return // dev build — skip
	}

	log.Printf("update: checking for updates (current: %s) ...", currentVersion)

	hc := &http.Client{Timeout: 10 * time.Second}
	tag, err := latestTag(hc)
	if err != nil {
		log.Printf("update: check failed: %v", err)
		return
	}

	latest, err := parseVersion(tag)
	if err != nil {
		return
	}
	if latest <= cur {
		log.Printf("update: already up to date (%s)", currentVersion)
		return
	}

	log.Printf("update: new version %s available — downloading %s ...", tag, asset)

	exe, err := os.Executable()
	if err != nil {
		log.Printf("update: cannot locate executable: %v", err)
		return
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		log.Printf("update: eval symlinks: %v", err)
		return
	}

	dlc := &http.Client{Timeout: 3 * time.Minute}
	if err := downloadAndReplace(dlc, downloadBase+asset, exe); err != nil {
		log.Printf("update: failed: %v", err)
		return
	}

	log.Printf("update: updated to %s — restarting", tag)
	reexec(exe)
}

// AssetForClient returns the release asset filename for the current client platform.
func AssetForClient() string {
	switch {
	case runtime.GOOS == "windows":
		return "supervpn-client-windows-amd64.exe"
	case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64":
		return "supervpn-client-darwin-arm64"
	default:
		return "supervpn-client-darwin-amd64"
	}
}

const AssetServer = "supervpn-server"

func latestTag(c *http.Client) (string, error) {
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var r struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	if r.TagName == "" {
		return "", fmt.Errorf("empty tag_name")
	}
	return r.TagName, nil
}

func parseVersion(v string) (int, error) {
	return strconv.Atoi(strings.TrimPrefix(v, "b"))
}

func downloadAndReplace(c *http.Client, url, exe string) error {
	resp, err := c.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	tmp := exe + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	// On Windows: rename running exe to .old first.
	// Windows allows renaming a running exe because the kernel holds it by handle, not name.
	if runtime.GOOS == "windows" {
		old := exe + ".old"
		os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("rename current→.old: %w", err)
		}
	}
	if err := os.Rename(tmp, exe); err != nil {
		return fmt.Errorf("rename .new→current: %w", err)
	}
	return nil
}
