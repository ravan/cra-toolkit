package policykit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	kevURL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevCacheDir = "suse-cra-toolkit"
	kevFile     = "kev.json"
	kevMaxAge   = 24 * time.Hour
)

// KEVCatalog holds parsed CISA Known Exploited Vulnerabilities data.
type KEVCatalog struct {
	CatalogDate string
	CVEs        map[string]bool
}

// Contains reports whether the catalog includes the given CVE identifier.
func (k *KEVCatalog) Contains(cve string) bool {
	return k.CVEs[cve]
}

// MatchFindings returns the subset of cves that appear in the KEV catalog.
func (k *KEVCatalog) MatchFindings(cves []string) []string {
	var matches []string
	for _, cve := range cves {
		if k.CVEs[cve] {
			matches = append(matches, cve)
		}
	}
	return matches
}

// kevJSON mirrors the CISA KEV JSON structure for parsing.
type kevJSON struct {
	DateReleased    string         `json:"dateReleased"`
	Vulnerabilities []kevVulnEntry `json:"vulnerabilities"`
}

type kevVulnEntry struct {
	CVEID string `json:"cveID"`
}

// ParseKEV reads CISA KEV JSON from r and returns a KEVCatalog.
func ParseKEV(r io.Reader) (*KEVCatalog, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading KEV data: %w", err)
	}

	var raw kevJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing KEV JSON: %w", err)
	}

	cat := &KEVCatalog{
		CatalogDate: raw.DateReleased,
		CVEs:        make(map[string]bool, len(raw.Vulnerabilities)),
	}
	for _, v := range raw.Vulnerabilities {
		if v.CVEID != "" {
			cat.CVEs[v.CVEID] = true
		}
	}
	return cat, nil
}

// LoadKEV loads a KEV catalog from a local file, XDG cache, or the network.
// If localPath is non-empty it is used directly. Otherwise the function checks
// $XDG_CACHE_HOME/suse-cra-toolkit/kev.json (falling back to ~/.cache/...)
// and fetches from CISA if the cached copy is missing or older than 24 hours.
func LoadKEV(localPath string) (*KEVCatalog, error) {
	if localPath != "" {
		return loadKEVFromFile(localPath)
	}

	cachePath := kevCachePath()

	info, err := os.Stat(cachePath)
	if err == nil && time.Since(info.ModTime()) < kevMaxAge {
		return loadKEVFromFile(cachePath)
	}

	// Fetch from network.
	resp, err := http.Get(kevURL) //nolint:gosec,noctx // static URL
	if err != nil {
		// If we have a stale cache, prefer it over a network error.
		if info != nil {
			return loadKEVFromFile(cachePath)
		}
		return nil, fmt.Errorf("fetching KEV catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if info != nil {
			return loadKEVFromFile(cachePath)
		}
		return nil, fmt.Errorf("fetching KEV catalog: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading KEV response: %w", err)
	}

	// Cache the response.
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err == nil {
		_ = os.WriteFile(cachePath, body, 0o644)
	}

	return ParseKEV(bytes.NewReader(body))
}

func loadKEVFromFile(path string) (*KEVCatalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening KEV file %s: %w", path, err)
	}
	defer f.Close()
	return ParseKEV(f)
}

func kevCachePath() string {
	cacheDir := os.Getenv("XDG_CACHE_HOME")
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		cacheDir = filepath.Join(home, ".cache")
	}
	return filepath.Join(cacheDir, kevCacheDir, kevFile)
}
