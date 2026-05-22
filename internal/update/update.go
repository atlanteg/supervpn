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
	githubAPIURL = "https://api.github.com/repos/" + releasesRepo + "/releases/latest"
	// githubDLBase uses the tag-specific URL (not /latest/download/) to avoid
	// CDN caching lag where the API returns a new tag but the CDN still serves
	// the previous binary, causing an infinite update-restart loop.
	githubDLBase = "https://github.com/" + releasesRepo + "/releases/download/"
)

// CheckAndUpdate checks for a newer release using GitHub and optional mirror
// base URLs (each mirror must serve GET {base}/version → plain-text "bN",
// and GET {base}/{asset} → binary). Tries each source in order; first success
// wins for both version check and download. Does not return on success.
func CheckAndUpdate(currentVersion, asset string, mirrors []string) {
	cur, err := parseVersion(currentVersion)
	if err != nil {
		return // dev build — skip
	}

	log.Printf("update: checking for updates (current: %s) ...", currentVersion)

	hc := &http.Client{Timeout: 10 * time.Second}

	tag, tagSrc, err := resolveLatestTag(hc, mirrors)
	if err != nil {
		log.Printf("update: check failed (all sources): %v", err)
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

	log.Printf("update: new version %s available (via %s) — downloading %s ...", tag, tagSrc, asset)

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
	if err := downloadWithFallback(dlc, tag, asset, exe, mirrors); err != nil {
		log.Printf("update: download failed (all sources): %v", err)
		return
	}

	log.Printf("update: updated to %s — restarting", tag)
	reexec(exe)
}

// resolveLatestTag tries GitHub API first, then each mirror's /version endpoint.
// Returns the tag, the source label, and any error if all sources failed.
func resolveLatestTag(c *http.Client, mirrors []string) (tag, src string, err error) {
	// GitHub API
	if t, e := latestTagFromGitHub(c); e == nil {
		return t, "github", nil
	} else {
		err = e
	}

	// Mirrors: GET {base}/version → plain text "bN"
	for _, m := range mirrors {
		url := strings.TrimRight(m, "/") + "/version"
		if t, e := latestTagFromURL(c, url); e == nil {
			return t, m, nil
		}
	}

	return "", "", fmt.Errorf("github: %w; mirrors tried: %d", err, len(mirrors))
}

func latestTagFromGitHub(c *http.Client) (string, error) {
	req, _ := http.NewRequest("GET", githubAPIURL, nil)
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
		return "", fmt.Errorf("empty tag_name in GitHub response")
	}
	return r.TagName, nil
}

// latestTagFromURL fetches a plain-text version string (e.g. "b101") from url.
func latestTagFromURL(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32))
	if err != nil {
		return "", err
	}
	tag := strings.TrimSpace(string(body))
	if tag == "" {
		return "", fmt.Errorf("empty version response")
	}
	return tag, nil
}

// downloadWithFallback tries GitHub (tag-specific URL) first, then each mirror.
func downloadWithFallback(c *http.Client, tag, asset, exe string, mirrors []string) error {
	urls := []string{githubDLBase + tag + "/" + asset}
	for _, m := range mirrors {
		urls = append(urls, strings.TrimRight(m, "/")+"/"+asset)
	}

	var lastErr error
	for _, url := range urls {
		if err := downloadAndReplace(c, url, exe); err != nil {
			log.Printf("update: download from %s failed: %v", url, err)
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
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

// AssetForClientGUI returns the release asset filename for the Win32/Walk GUI build.
// On Windows this is the default (Walk/GDI) variant; on macOS it is the arch-specific binary.
func AssetForClientGUI() string {
	switch {
	case runtime.GOOS == "windows":
		return "supervpn-client-gui-windows-amd64.exe"
	case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64":
		return "supervpn-client-gui-darwin-arm64"
	default:
		return "supervpn-client-gui-darwin-amd64"
	}
}

// AssetForClientGUIFyne returns the release asset filename for the Fyne GUI build.
// On Windows this is the OpenGL/Fyne variant; on macOS same as AssetForClientGUI.
func AssetForClientGUIFyne() string {
	switch {
	case runtime.GOOS == "windows":
		return "supervpn-client-gui-windows-fyne-amd64.exe"
	case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64":
		return "supervpn-client-gui-darwin-arm64"
	default:
		return "supervpn-client-gui-darwin-amd64"
	}
}

// AssetForSeema returns the release asset filename for the seema pre-configured client.
func AssetForSeema() string {
	return "supervpn-seema-windows-amd64.exe"
}

const AssetServer = "supervpn-server"

// FetchAsset downloads one release asset from the tag-specific GitHub URL to
// destPath, creating parent directories as needed. Written atomically via a
// .new temp file. Intended for servers pre-populating their mirror directory.
func FetchAsset(tag, asset, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	c := &http.Client{Timeout: 3 * time.Minute}
	return downloadAndReplace(c, githubDLBase+tag+"/"+asset, destPath)
}

// CleanupOldFiles removes any *.old files sitting next to the running
// executable — leftovers from a previous Windows self-update where the old
// binary is renamed to .old before the new one is placed.  Safe to call on
// every startup; silently skips files it cannot remove (e.g. still locked).
func CleanupOldFiles() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), "*.old"))
	for _, f := range matches {
		if err := os.Remove(f); err == nil {
			log.Printf("update: removed stale backup %s", filepath.Base(f))
		}
	}
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
