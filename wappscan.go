package main

import (
        "bufio"
        "context"
        "crypto/tls"
        "encoding/base64"
        "encoding/csv"
        "encoding/json"
        "flag"
        "fmt"
        "io"
        "math/rand"
        "net"
        "net/http"
        "net/http/cookiejar"
        "net/url"
        "os"
        "os/exec"
        "path/filepath"
        "runtime"
        "regexp"
        "sort"
        "strconv"
        "strings"
        "sync"
        "time"

        "github.com/chromedp/chromedp"
        wappalyzer "github.com/projectdiscovery/wappalyzergo"
        "github.com/spaolacci/murmur3"
)

const (
        GREEN  = "\033[32m"
        RED    = "\033[31m"
        BLUE   = "\033[34m"
        YELLOW = "\033[33m"
        RESET  = "\033[0m"
        BOLD   = "\033[1m"
        CYAN   = "\033[36m"
)

const version = "1.0.8"

func showBanner(noColor bool) {
	banner := `
                                                                                
▄▄      ▄▄                                 ▄▄▄▄                                 
██      ██                               ▄█▀▀▀▀█                                
▀█▄ ██ ▄█▀  ▄█████▄  ██▄███▄   ██▄███▄   ██▄        ▄█████▄   ▄█████▄  ██▄████▄ 
 ██ ██ ██   ▀ ▄▄▄██  ██▀  ▀██  ██▀  ▀██   ▀████▄   ██▀    ▀   ▀ ▄▄▄██  ██▀   ██ 
 ███▀▀███  ▄██▀▀▀██  ██    ██  ██    ██       ▀██  ██        ▄██▀▀▀██  ██    ██ 
 ███  ███  ██▄▄▄███  ███▄▄██▀  ███▄▄██▀  █▄▄▄▄▄█▀  ▀██▄▄▄▄█  ██▄▄▄███  ██    ██ 
 ▀▀▀  ▀▀▀   ▀▀▀▀ ▀▀  ██ ▀▀▀    ██ ▀▀▀     ▀▀▀▀▀      ▀▀▀▀▀    ▀▀▀▀ ▀▀  ▀▀    ▀▀ 
                     ██        ██                                               
                                                                                             
`
	if noColor {
		fmt.Fprint(os.Stderr, banner)
		fmt.Fprintf(os.Stderr, "               v%s | @mr-rizwan-syed\n\n", version)
		return
	}
	fmt.Fprintf(os.Stderr, "%s%s%s", CYAN, banner, RESET)
	fmt.Fprintf(os.Stderr, "               %sv%s%s | %s@mr-rizwan-syed%s\n\n",
		BOLD, version, RESET, YELLOW, RESET)
}
func selfUpdate() error {
        goos := runtime.GOOS
        goarch := runtime.GOARCH

        downloadURL := fmt.Sprintf(
                "https://github.com/mr-rizwan-syed/wappscan/releases/latest/download/wappscan_%s_%s",
                goos, goarch)

        fmt.Fprintf(os.Stderr, "[*] Updating wappscan from %s\n", downloadURL)

        resp, err := http.Get(downloadURL)
        if err != nil {
                return fmt.Errorf("download failed: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != 200 {
                // Fallback: try go install
                fmt.Fprintf(os.Stderr, "[*] Binary not found, trying go install...\n")
                cmd := exec.Command("go", "install", "github.com/mr-rizwan-syed/wappscan@latest")
                cmd.Stdout = os.Stdout
                cmd.Stderr = os.Stderr
                if err := cmd.Run(); err != nil {
                        return fmt.Errorf("go install failed: %w", err)
                }
                fmt.Fprintf(os.Stderr, "[+] Updated successfully via go install\n")
                return nil
        }

        exePath, err := os.Executable()
        if err != nil {
                return fmt.Errorf("cannot find executable path: %w", err)
        }

        tmpFile := exePath + ".tmp"
        out, err := os.Create(tmpFile)
        if err != nil {
                return fmt.Errorf("cannot create temp file: %w", err)
        }

        _, err = io.Copy(out, resp.Body)
        out.Close()
        if err != nil {
                os.Remove(tmpFile)
                return fmt.Errorf("download incomplete: %w", err)
        }

        os.Chmod(tmpFile, 0755)
        if err := os.Rename(tmpFile, exePath); err != nil {
                os.Remove(tmpFile)
                return fmt.Errorf("cannot replace binary: %w", err)
        }

        fmt.Fprintf(os.Stderr, "[+] Updated successfully to latest version\n")
        return nil
}

type Match struct {
        AppName string `json:"app_name"`
        Version string `json:"version"`
}

type WebAnalyzeLike struct {
        Hostname string  `json:"hostname"`
        Matches  []Match `json:"matches"`
}

func normalizeInput(input string) string {
        return strings.TrimSpace(input)
}

func parseTechVersion(tech string) (string, string) {
        if strings.Contains(tech, ":") {
                parts := strings.SplitN(tech, ":", 2)
                return parts[0], parts[1]
        }
        return tech, ""
}

func isTemporaryErr(err error) bool {
        if err == nil {
                return false
        }

        if ne, ok := err.(net.Error); ok && ne.Timeout() {
                return true
        }

        msg := err.Error()
        return strings.Contains(msg, "context deadline exceeded") ||
                strings.Contains(msg, "connection reset") ||
                strings.Contains(msg, "broken pipe") ||
                strings.Contains(msg, "i/o timeout")
}

// mergeTechs merges one or more tech maps into dst.
func mergeTechs(dst map[string]struct{}, srcs ...map[string]struct{}) {
        for _, src := range srcs {
                for k := range src {
                        dst[k] = struct{}{}
                }
        }
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+\bsrc=["']([^"']+)["']`)

// extractScriptSrcs parses HTML body and returns all <script src="..."> URL values.
func extractScriptSrcs(body []byte) []string {
        matches := scriptSrcRe.FindAllSubmatch(body, -1)
        var srcs []string
        for _, m := range matches {
                if len(m) > 1 {
                        src := strings.TrimSpace(string(m[1]))
                        if src != "" {
                                srcs = append(srcs, src)
                        }
                }
        }
        return srcs
}

// resolveURL resolves a potentially relative URL against a base URL.
func resolveURL(base, ref string) string {
        // Handle protocol-relative URLs
        if strings.HasPrefix(ref, "//") {
                ref = "https:" + ref
        }

        baseURL, err := url.Parse(base)
        if err != nil {
                return ""
        }

        refURL, err := url.Parse(ref)
        if err != nil {
                return ""
        }

        resolved := baseURL.ResolveReference(refURL)
        return resolved.String()
}

// fetchPartialJS fetches the first maxBytes of a JS file using a Range header.
func fetchPartialJS(client *http.Client, jsURL, userAgent string, maxBytes int) []byte {
        req, err := http.NewRequest("GET", jsURL, nil)
        if err != nil {
                return nil
        }

        req.Header.Set("User-Agent", userAgent)
        req.Header.Set("Accept", "*/*")
        req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", maxBytes-1))

        resp, err := client.Do(req)
        if err != nil {
                return nil
        }
        defer resp.Body.Close()

        // Accept both 200 (full) and 206 (partial) responses
        if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
                return nil
        }

        data, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)))
        if err != nil {
                return nil
        }
        return data
}

// fetchJSContent extracts script src URLs from the HTML body, resolves them,
// and fetches partial content concurrently. Returns concatenated JS bytes.
func fetchJSContent(client *http.Client, baseURL string, body []byte, userAgent string, maxFiles, maxBytes int) []byte {
        rawSrcs := extractScriptSrcs(body)
        if len(rawSrcs) == 0 {
                return nil
        }

        // Deduplicate and resolve URLs
        seen := make(map[string]bool)
        var jsURLs []string
        for _, src := range rawSrcs {
                resolved := resolveURL(baseURL, src)
                if resolved == "" {
                        continue
                }
                if !strings.HasPrefix(resolved, "http://") && !strings.HasPrefix(resolved, "https://") {
                        continue
                }
                if seen[resolved] {
                        continue
                }
                seen[resolved] = true
                jsURLs = append(jsURLs, resolved)
                if len(jsURLs) >= maxFiles {
                        break
                }
        }

        if len(jsURLs) == 0 {
                return nil
        }

        // Fetch concurrently
        type result struct {
                data []byte
        }
        results := make([]result, len(jsURLs))
        var wg sync.WaitGroup

        for i, jsURL := range jsURLs {
                wg.Add(1)
                go func(idx int, u string) {
                        defer wg.Done()
                        results[idx] = result{data: fetchPartialJS(client, u, userAgent, maxBytes)}
                }(i, jsURL)
        }
        wg.Wait()

        // Concatenate all fetched JS content
        var buf []byte
        for _, r := range results {
                if len(r.data) > 0 {
                        buf = append(buf, '\n')
                        buf = append(buf, r.data...)
                }
        }
        return buf
}

// errorPageSignatures maps known error page patterns to technology names.
var errorPageSignatures = []struct {
        pattern *regexp.Regexp
        tech    string
}{
        {regexp.MustCompile(`(?i)<!-- a padding to disable MSIE and Chrome friendly error page -->`), "Nginx"},
        {regexp.MustCompile(`(?i)<address>Apache[^<]*</address>`), "Apache"},
        {regexp.MustCompile(`(?i)<b>IIS\s+[\d.]+</b>`), "Microsoft IIS"},
        {regexp.MustCompile(`(?i)openresty`), "OpenResty"},
        {regexp.MustCompile(`(?i)cloudflare`), "Cloudflare"},
        {regexp.MustCompile(`(?i)AkamaiGHost`), "Akamai"},
}

// detectFromErrorPage checks error page body and headers for technology signatures
// that might not be caught by wappalyzergo.
func detectFromErrorPage(headers map[string][]string, body []byte) map[string]struct{} {
        techs := make(map[string]struct{})

        // Check body patterns
        for _, sig := range errorPageSignatures {
                if sig.pattern.Match(body) {
                        techs[sig.tech] = struct{}{}
                }
        }

        // Check server header for known reverse proxies
        if serverVals, ok := headers["Server"]; ok {
                for _, sv := range serverVals {
                        svl := strings.ToLower(sv)
                        if strings.Contains(svl, "nginx") {
                                techs["Nginx"] = struct{}{}
                        }
                        if strings.Contains(svl, "apache") {
                                techs["Apache"] = struct{}{}
                        }
                        if strings.Contains(svl, "cloudflare") {
                                techs["Cloudflare"] = struct{}{}
                        }
                }
        }

        return techs
}

// waybackResponse represents the Wayback Machine availability API response.
type waybackResponse struct {
        ArchivedSnapshots struct {
                Closest struct {
                        URL       string `json:"url"`
                        Available bool   `json:"available"`
                        Status    string `json:"status"`
                } `json:"closest"`
        } `json:"archived_snapshots"`
}

// fetchWaybackPage queries the Wayback Machine for a cached version of the URL
// and returns the response headers and body if available.
func fetchWaybackPage(client *http.Client, targetURL, userAgent string) (map[string][]string, []byte) {
        // Query Wayback Machine availability API
        parsed, err := url.Parse(targetURL)
        if err != nil {
                return nil, nil
        }
        host := parsed.Hostname()

        apiURL := "https://archive.org/wayback/available?url=" + url.QueryEscape(host)
        req, err := http.NewRequest("GET", apiURL, nil)
        if err != nil {
                return nil, nil
        }
        req.Header.Set("User-Agent", userAgent)

        resp, err := client.Do(req)
        if err != nil {
                return nil, nil
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                return nil, nil
        }

        apiBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
        if err != nil {
                return nil, nil
        }

        var wb waybackResponse
        if err := json.Unmarshal(apiBody, &wb); err != nil {
                return nil, nil
        }

        if !wb.ArchivedSnapshots.Closest.Available || wb.ArchivedSnapshots.Closest.URL == "" {
                return nil, nil
        }

        // Fetch the cached page
        cachedURL := wb.ArchivedSnapshots.Closest.URL
        // Ensure HTTPS
        cachedURL = strings.Replace(cachedURL, "http://web.archive.org", "https://web.archive.org", 1)

        cacheReq, err := http.NewRequest("GET", cachedURL, nil)
        if err != nil {
                return nil, nil
        }
        cacheReq.Header.Set("User-Agent", userAgent)

        cacheResp, err := client.Do(cacheReq)
        if err != nil {
                return nil, nil
        }
        defer cacheResp.Body.Close()

        // Limit body to 2MB
        cachedBody, err := io.ReadAll(io.LimitReader(cacheResp.Body, 2*1024*1024))
        if err != nil {
                return nil, nil
        }

        // Extract original headers from Wayback page if available,
        // but primarily return the cached body for fingerprinting.
        // We pass nil headers so wappalyzergo focuses on body patterns.
        return nil, cachedBody
}

// stripWaybackURLs removes Wayback Machine URL prefixes from script src URLs,
// converting e.g. "https://web.archive.org/web/20241224202319js_/https://cdn.example.com/lib.js"
// back to "https://cdn.example.com/lib.js".
var waybackURLRe = regexp.MustCompile(`https?://web\.archive\.org/web/[0-9]+(?:js_|im_|cs_|if_)?/`)

func stripWaybackPrefix(rawURL string) string {
        return waybackURLRe.ReplaceAllString(rawURL, "")
}

// extractOriginalScriptSrcs extracts script src URLs from a Wayback cached page
// and strips the archive.org prefixes to get original URLs.
func extractOriginalScriptSrcs(body []byte) []string {
        rawSrcs := extractScriptSrcs(body)
        var originals []string
        for _, src := range rawSrcs {
                cleaned := stripWaybackPrefix(src)
                // Skip Wayback Machine's own injected scripts
                if strings.Contains(cleaned, "web-static.archive.org") ||
                        strings.Contains(cleaned, "archive.org/_static") {
                        continue
                }
                originals = append(originals, cleaned)
        }
        return originals
}

// -----------------------------------------------------------------------------
// New Detection Techniques: Cookies, Meta Tags, Favicon, Inline Scripts
// -----------------------------------------------------------------------------

// detectFromCookies checks for known cookie names that identify technologies.
func detectFromCookies(cookies []*http.Cookie) map[string]struct{} {
        techs := make(map[string]struct{})
        for _, c := range cookies {
                name := c.Name
                if name == "PHPSESSID" {
                        techs["PHP"] = struct{}{}
                } else if name == "JSESSIONID" {
                        techs["Java"] = struct{}{}
                } else if name == "ASP.NET_SessionId" {
                        techs["ASP.NET"] = struct{}{}
                } else if name == "laravel_session" {
                        techs["Laravel"] = struct{}{}
                } else if name == "__cfduid" || name == "cf_clearance" {
                        techs["Cloudflare"] = struct{}{}
                } else if name == "_ga" || name == "_gid" {
                        techs["Google Analytics"] = struct{}{}
                } else if name == "XSRF-TOKEN" {
                        // Ambiguous, but often associated with these
                        // techs["Angular"] = struct{}{}
                        // techs["Laravel"] = struct{}{}
                } else if strings.HasPrefix(name, "wp-settings-") || strings.HasPrefix(name, "wordpress_") {
                        techs["WordPress"] = struct{}{}
                } else if name == "connect.sid" {
                        techs["Express"] = struct{}{}
                } else if name == "csrftoken" {
                        techs["Django"] = struct{}{}
                } else if name == "rack.session" {
                        techs["Ruby on Rails"] = struct{}{}
                } else if name == "beget" {
                        techs["BeGet"] = struct{}{}
                } else if name == "bitrix_sessid" {
                        techs["1C-Bitrix"] = struct{}{}
                }
        }
        return techs
}

var metaGeneratorRe = regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
var metaAppRe = regexp.MustCompile(`(?i)<meta\s+name=["']application-name["']\s+content=["']([^"']+)["']`)

// extractMetaTechs parses <meta> tags for generator or application-name.
func extractMetaTechs(body []byte) map[string]struct{} {
        techs := make(map[string]struct{})

        // Generator tag
        if matches := metaGeneratorRe.FindSubmatch(body); len(matches) > 1 {
                content := string(matches[1])
                lower := strings.ToLower(content)
                if strings.Contains(lower, "wordpress") {
                        techs["WordPress"] = struct{}{}
                } else if strings.Contains(lower, "joomla") {
                        techs["Joomla"] = struct{}{}
                } else if strings.Contains(lower, "drupal") {
                        techs["Drupal"] = struct{}{}
                } else if strings.Contains(lower, "hugo") {
                        techs["Hugo"] = struct{}{}
                } else if strings.Contains(lower, "jekyll") {
                        techs["Jekyll"] = struct{}{}
                } else if strings.Contains(lower, "shopify") {
                        techs["Shopify"] = struct{}{}
                } else if strings.Contains(lower, "wix") {
                        techs["Wix"] = struct{}{}
                } else if strings.Contains(lower, "squarespace") {
                        techs["Squarespace"] = struct{}{}
                } else if strings.Contains(lower, "gatsby") {
                        techs["Gatsby"] = struct{}{}
                } else if strings.Contains(lower, "next.js") {
                        techs["Next.js"] = struct{}{}
                } else if strings.Contains(lower, "nuxt") {
                        techs["Nuxt.js"] = struct{}{}
                } else {
                        // Capture unknown generators too? For now, just specific ones.
                        // techs[content] = struct{}{}
                }
        }

        // Application-name tag
        if matches := metaAppRe.FindSubmatch(body); len(matches) > 1 {
                content := string(matches[1])
                if strings.ToLower(content) == "next.js" {
                        techs["Next.js"] = struct{}{}
                }
        }

        return techs
}



// -----------------------------------------------------------------------------
// In-Process Detection: Title, Favicon Hash
// -----------------------------------------------------------------------------

// fetchFaviconHash fetches /favicon.ico and returns its mmh3 hash.
// This replaces the per-target httpx subprocess with an in-process computation.
func fetchFaviconHash(client *http.Client, targetURL, userAgent string) (int32, bool) {
        parsed, err := url.Parse(targetURL)
        if err != nil {
                return 0, false
        }
        faviconURL := fmt.Sprintf("%s://%s/favicon.ico", parsed.Scheme, parsed.Host)

        req, err := http.NewRequest("GET", faviconURL, nil)
        if err != nil {
                return 0, false
        }
        req.Header.Set("User-Agent", userAgent)

        resp, err := client.Do(req)
        if err != nil {
                return 0, false
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                return 0, false
        }

        data, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
        if err != nil || len(data) == 0 {
                return 0, false
        }

        encoded := base64.StdEncoding.EncodeToString(data)
        h := murmur3.Sum32([]byte(encoded))
        return int32(h), true
}

var titleRe = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

// extractTitle extracts content of <title> tag using regex.
func extractTitle(body []byte) string {
        matches := titleRe.FindSubmatch(body)
        if len(matches) > 1 {
                return strings.TrimSpace(string(matches[1]))
        }
        return ""
}

// detectFromTitle checks the title against a loaded pattern DB.
func detectFromTitle(title string, patterns map[string]string) map[string]struct{} {
        techs := make(map[string]struct{})
        if title == "" {
                return techs
        }
        lowerTitle := strings.ToLower(title)
        
        for pattern, tech := range patterns {
                // Determine check based on pattern content?
                // Simple case-insensitive contains
                if strings.Contains(lowerTitle, strings.ToLower(pattern)) {
                        techs[tech] = struct{}{}
                }
        }
        return techs
}

// loadTitlePatterns loads CSV: pattern,technology
func loadTitlePatterns(path string) (map[string]string, error) {
        f, err := os.Open(path)
        if err != nil {
                return nil, err
        }
        defer f.Close()

        patterns := make(map[string]string)
        reader := csv.NewReader(f)
        reader.FieldsPerRecord = -1 // Allow variable number of fields

        records, err := reader.ReadAll()
        if err != nil {
                return nil, err
        }

        for _, record := range records {
                if len(record) < 1 {
                        continue
                }
                
                tech := strings.TrimSpace(record[0])
                if strings.ToLower(tech) == "technology" || strings.ToLower(tech) == "pattern" {
                         continue
                }

                if len(record) == 1 {
                        // Implied pattern = technology
                        patterns[strings.ToLower(tech)] = tech
                        continue
                }

                // record[1:] are patterns
                for i := 1; i < len(record); i++ {
                        pat := strings.TrimSpace(record[i])
                        if pat != "" {
                                patterns[strings.ToLower(pat)] = tech
                        }
                }
        }
        return patterns, nil
}


// loadFaviconHashes loads the CSV database of hashes.
func loadFaviconHashes(path string) (map[int32]string, error) {
        f, err := os.Open(path)
        if err != nil {
                return nil, err
        }
        defer f.Close()

        db := make(map[int32]string)
        reader := csv.NewReader(f)
        
        // skip header
        _, _ = reader.Read()

        for {
                record, err := reader.Read()
                if err == io.EOF {
                        break
                }
                if err != nil {
                        continue
                }
                if len(record) < 2 {
                        continue
                }
                
                h, err := strconv.ParseInt(record[0], 10, 32)
                if err != nil {
                        continue
                }
                tech := normalizeInput(record[1])
                db[int32(h)] = tech
        }
        return db, nil
}

var inlineScriptRe = regexp.MustCompile(`(?i)<script[^>]*>([\s\S]*?)</script>`)

// detectFromInlineScripts checks script content for framework signatures.
func detectFromInlineScripts(body []byte) map[string]struct{} {
        techs := make(map[string]struct{})
        matches := inlineScriptRe.FindAllSubmatch(body, -1)
        
        for _, m := range matches {
                if len(m) < 2 {
                        continue
                }
                content := string(m[1])
                
                if strings.Contains(content, "__NEXT_DATA__") {
                        techs["Next.js"] = struct{}{}
                        techs["React"] = struct{}{}
                }
                if strings.Contains(content, "window.__NUXT__") || strings.Contains(content, "__NUXT__") {
                        techs["Nuxt.js"] = struct{}{}
                        techs["Vue.js"] = struct{}{}
                }
                if strings.Contains(content, "React.createElement") || strings.Contains(content, "ReactDOM.render") {
                        techs["React"] = struct{}{}
                }
                if strings.Contains(content, "Vue.createApp") || strings.Contains(content, "new Vue(") {
                        techs["Vue.js"] = struct{}{}
                }
                if strings.Contains(content, "ng-app") || strings.Contains(content, "angular.module") {
                        techs["AngularJS"] = struct{}{}
                }
                if strings.Contains(content, "gtag(") || strings.Contains(content, "GoogleAnalyticsObject") {
                        techs["Google Analytics"] = struct{}{}
                }
                if strings.Contains(content, "gtm.start") || strings.Contains(content, "GoogleTagManager") {
                        techs["Google Tag Manager"] = struct{}{}
                }
                if strings.Contains(content, "fbq(") && strings.Contains(content, "fbevents.js") {
                        techs["Facebook Pixel"] = struct{}{}
                }
                if strings.Contains(content, "Shopify.shop") {
                        techs["Shopify"] = struct{}{}
                }
                if strings.Contains(content, "__gatsby") {
                        techs["Gatsby"] = struct{}{}
                        techs["React"] = struct{}{}
                }
                if strings.Contains(content, "svelte-") {
                        techs["Svelte"] = struct{}{}
                }
                if strings.Contains(content, "wp-emoji") {
                        techs["WordPress"] = struct{}{}
                }
        }
        return techs
}
func loadUserAgents(filePath string) ([]string, error) {
        file, err := os.Open(filePath)
        if err != nil {
                return nil, err
        }
        defer file.Close()

        var uas []string
        scanner := bufio.NewScanner(file)

        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line != "" {
                        uas = append(uas, line)
                }
        }
        if scanner.Err() != nil {
                return nil, scanner.Err()
        }

        if len(uas) == 0 {
                return nil, fmt.Errorf("no user-agents found in file")
        }

        return uas, nil
}

func pickRandomUA(uaList []string) string {
        return uaList[rand.Intn(len(uaList))]
}

func tryRequest(client *http.Client, url string, retries int, userAgent string) (*http.Response, []byte, error) {
        var lastErr error

        for i := 0; i <= retries; i++ {

                req, err := http.NewRequest("GET", url, nil)
                if err != nil {
                        return nil, nil, err
                }

                req.Header.Set("User-Agent", userAgent)
                req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
                req.Header.Set("Accept-Language", "en-US,en;q=0.9")
                req.Header.Set("Accept-Encoding", "identity")
                req.Header.Set("Sec-Fetch-Dest", "document")
                req.Header.Set("Sec-Fetch-Mode", "navigate")
                req.Header.Set("Sec-Fetch-Site", "none")
                req.Header.Set("Sec-Fetch-User", "?1")
                req.Header.Set("Upgrade-Insecure-Requests", "1")


                resp, err := client.Do(req)
                if err != nil {
                        lastErr = err
                        if isTemporaryErr(err) {
                                time.Sleep(time.Duration(i+1) * time.Second)
                                continue
                        }
                        return nil, nil, err
                }

                body, err := io.ReadAll(resp.Body)
                resp.Body.Close()

                if err != nil {
                        lastErr = err
                        if isTemporaryErr(err) {
                                time.Sleep(time.Duration(i+1) * time.Second)
                                continue
                        }
                        return nil, nil, err
                }

                return resp, body, nil
        }

        return nil, nil, lastErr
}

// configDir returns the wappscan config directory (~/.config/wappscan).
func configDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".config", "wappscan")
}

const githubRawBase = "https://raw.githubusercontent.com/mr-rizwan-syed/wappscan/main/"

// ensureDataFile checks if a data file exists at path; if not, downloads it
// from the GitHub repo and saves it to configDir.
func ensureDataFile(path, filename string, verbose bool) string {
	// If user specified an explicit path that exists, use it
	if _, err := os.Stat(path); err == nil {
		return path
	}

	// Ensure config directory exists
	dir := configDir()
	os.MkdirAll(dir, 0755)

	dest := filepath.Join(dir, filename)
	if _, err := os.Stat(dest); err == nil {
		return dest
	}

	// Download from GitHub
	downloadURL := githubRawBase + filename
	if verbose {
		fmt.Fprintf(os.Stderr, "INFO Downloading %s from %s...\n", filename, downloadURL)
	}

	resp, err := http.Get(downloadURL)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "WARNING Failed to download %s: %v\n", filename, err)
		}
		return path
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		if verbose {
			fmt.Fprintf(os.Stderr, "WARNING Failed to download %s: HTTP %d\n", filename, resp.StatusCode)
		}
		return path
	}

	f, err := os.Create(dest)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "WARNING Failed to save %s: %v\n", dest, err)
		}
		return path
	}
	defer f.Close()

	io.Copy(f, resp.Body)
	if verbose {
		fmt.Fprintf(os.Stderr, "INFO Saved %s to %s\n", filename, dest)
	}
	return dest
}

func main() {
        var singleURL string
        var listFile string
        var concurrency int
        var jsonOut bool
        var timeoutSec int
        var retries int
        var verbose bool
        var silent bool
        var outputFile string
        var showVersion bool
        var doUpdate bool
        var proxyURL string
        var rateLimit int
        var noColor bool

        var uaCustom string
        var uaFile string

        flag.StringVar(&singleURL, "u", "", "single target URL/domain (example: test.com or https://test.com)")
        flag.StringVar(&listFile, "l", "", "file containing list of domains/subdomains")
        flag.IntVar(&concurrency, "c", 20, "concurrency level")
        flag.BoolVar(&jsonOut, "json", false, "output JSON in webanalyze-like format")
        flag.IntVar(&timeoutSec, "t", 25, "timeout in seconds")
        flag.IntVar(&retries, "r", 1, "retries for temporary errors/timeouts")
        flag.BoolVar(&verbose, "v", false, "verbose mode (prints errors/debug)")
        flag.BoolVar(&silent, "silent", false, "silent mode (no banner, no stdout)")
        flag.StringVar(&outputFile, "o", "", "output file to save results")
        flag.BoolVar(&showVersion, "version", false, "show version and exit")
        flag.BoolVar(&doUpdate, "update", false, "update wappscan to latest version")
        flag.StringVar(&proxyURL, "proxy", "", "HTTP/SOCKS5 proxy URL (e.g. http://127.0.0.1:8080)")
        flag.IntVar(&rateLimit, "rate-limit", 0, "max requests per second (0 = unlimited)")
        flag.BoolVar(&noColor, "no-color", false, "disable colored output")

        flag.StringVar(&uaCustom, "ua", "", "custom User-Agent (optional)")
        flag.StringVar(&uaFile, "ua-file", "user-agents.txt", "user-agent file path (default: user-agents.txt)")

        defaultFaviconDB := filepath.Join(configDir(), "favicon_hashes.csv")
        defaultTitleDB := filepath.Join(configDir(), "title_patterns.csv")

        var faviconDB string
        flag.StringVar(&faviconDB, "favicon-db", defaultFaviconDB, "path to favicon hash CSV database")
        
        var titleDB string
        flag.StringVar(&titleDB, "title-db", defaultTitleDB, "path to title patterns CSV")
        


        jsFetch := true
        var jsMax int
        var jsSize int
        var headless bool
        flag.IntVar(&jsMax, "js-max", 5, "max JS files to fetch per target")
        flag.IntVar(&jsSize, "js-size", 204800, "max bytes to fetch per JS file (default: 200KB)")
        flag.BoolVar(&headless, "headless", false, "use Headless Chrome to bypass WAFs/JS-checks (requires Chrome installed)")

        flag.Parse()

        // Handle -version
        if showVersion {
                fmt.Printf("wappscan v%s\n", version)
                return
        }

        // Handle -update
        if doUpdate {
                if err := selfUpdate(); err != nil {
                        fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
                        os.Exit(1)
                }
                return
        }

        // -silent combines quiet behavior
        quiet := silent

        // Show banner (unless silent/json)
        if !quiet && !jsonOut {
                showBanner(noColor)
        }

        // Check if Chrome is installed if headless is enabled
        if headless {
                chromePath := ""
                browsers := []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"}
                if runtime.GOOS == "darwin" {
                        browsers = append(browsers, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
                }
                for _, name := range browsers {
                        if path, err := exec.LookPath(name); err == nil {
                                chromePath = path
                                break
                        }
                }
                
                if chromePath == "" {
                        if verbose || !quiet {
                                fmt.Fprintln(os.Stderr, "WARNING: Headless mode requested but Chrome/Chromium not found in $PATH. Disabling headless mode.")
                        }
                        headless = false
                } else if verbose {
                        fmt.Fprintf(os.Stderr, "INFO Using Chrome at %s for headless mode\n", chromePath)
                }
        }

        wClient, err := wappalyzer.New()
        if err != nil {
                fmt.Println("Error initializing wappalyzer:", err)
                return
        }

        insecure := true
        transport := &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
                DialContext: (&net.Dialer{
                        Timeout: 10 * time.Second,
                }).DialContext,
        }

        // Proxy support
        if proxyURL != "" {
                proxyParsed, err := url.Parse(proxyURL)
                if err != nil {
                        fmt.Fprintf(os.Stderr, "Invalid proxy URL: %v\n", err)
                        os.Exit(1)
                }
                transport.Proxy = http.ProxyURL(proxyParsed)
                if verbose {
                        fmt.Fprintf(os.Stderr, "INFO Using proxy: %s\n", proxyURL)
                }
        }

        // Rate limiter
        var rateLimiter <-chan time.Time
        if rateLimit > 0 {
                rateLimiter = time.Tick(time.Second / time.Duration(rateLimit))
        }


        // Setup UA
        defaultUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        finalUA := defaultUA

        if uaCustom != "" {
                finalUA = uaCustom
        } else {
                uaList, err := loadUserAgents(uaFile)
                if err == nil && len(uaList) > 0 {
                        finalUA = pickRandomUA(uaList)
                }
        }

        // Ensure data files exist (download from GitHub if missing)
        faviconDB = ensureDataFile(faviconDB, "favicon_hashes.csv", verbose)
        titleDB = ensureDataFile(titleDB, "title_patterns.csv", verbose)

        // Load favicon DB
        var favHashes map[int32]string
        if fh, err := loadFaviconHashes(faviconDB); err == nil {
                favHashes = fh
        } else if verbose {
                fmt.Printf("Warning: could not load favicon DB %s: %v\n", faviconDB, err)
        }

        // Load Title Patterns
        var titlePatterns map[string]string
        if tp, err := loadTitlePatterns(titleDB); err == nil {
                titlePatterns = tp
        } else if verbose {
                fmt.Printf("Warning: could not load title patterns %s: %v\n", titleDB, err)
        }



        // Writers
        var stdoutWriter io.Writer = os.Stdout
        var fileWriter io.Writer = nil
        var fileHandle *os.File

        if quiet {
                stdoutWriter = io.Discard
        }

        if outputFile != "" {
                f, err := os.Create(outputFile)
                if err != nil {
                        fmt.Println("Error creating output file:", err)
                        return
                }
                fileHandle = f
                defer fileHandle.Close()
                fileWriter = f
        }

        sem := make(chan struct{}, concurrency)
        var wg sync.WaitGroup
        var mu sync.Mutex

        writeStdout := func(line string) {
                mu.Lock()
                fmt.Fprintln(stdoutWriter, line)
                mu.Unlock()
        }

        writeFile := func(line string) {
                if fileWriter == nil {
                        return
                }
                mu.Lock()
                fmt.Fprintln(fileWriter, line)
                mu.Unlock()
        }

        printError := func(host string, err error) {
                if verbose {
                        mu.Lock()
                        fmt.Fprintf(os.Stderr, "ERROR %s => %s\n", host, err.Error())
                        mu.Unlock()
                }
        }

        processTechOutput := func(url string, techMap map[string]struct{}) {
                if len(techMap) == 0 {
                        return
                }

                // JSON output
                if jsonOut {
                        matches := []Match{}

                        for tech := range techMap {
                                name, ver := parseTechVersion(tech)
                                matches = append(matches, Match{
                                        AppName: name,
                                        Version: ver,
                                })
                        }

                        sort.Slice(matches, func(i, j int) bool {
                                return matches[i].AppName < matches[j].AppName
                        })

                        obj := WebAnalyzeLike{
                                Hostname: url,
                                Matches:  matches,
                        }

                        b, _ := json.Marshal(obj)
                        line := string(b)

                        writeStdout(line)
                        writeFile(line)
                        return
                }

                // Normal output
                techList := []string{}
                for tech := range techMap {
                        name, ver := parseTechVersion(tech)
                        if ver != "" {
                                techList = append(techList, fmt.Sprintf("%s:%s", name, ver))
                        } else {
                                techList = append(techList, name)
                        }
                }

                sort.Strings(techList)

                plainLine := fmt.Sprintf("%s - [%s]", url, strings.Join(techList, ", "))
                colorLine := ""
                if noColor {
                        colorLine = plainLine
                } else {
                        colorLine = fmt.Sprintf("%s%s%s - %s[%s]%s",
                                CYAN, url, RESET,
                                GREEN, strings.Join(techList, ", "), RESET,
                        )
                }

                writeStdout(colorLine)
                writeFile(plainLine)
        }

        // fingerprintTarget runs fingerprinting on the response using multiple
        // detection techniques. JS fetching runs concurrently with other detections.
        fingerprintTarget := func(targetURL string, targetClient *http.Client, resp *http.Response, body []byte) {
                techMap := make(map[string]struct{})
                if verbose {
                        mu.Lock()
                        if resp == nil {
                                fmt.Fprintf(os.Stderr, "VERBOSE %s => No response (connection error?)\n", targetURL)
                        } else {
                                fmt.Fprintf(os.Stderr, "VERBOSE %s => HTTP %d, body=%d bytes\n", targetURL, resp.StatusCode, len(body))
                        }
                        mu.Unlock()
                }

                // Start JS fetch concurrently with other detections
                var jsContent []byte
                var jsWg sync.WaitGroup
                if jsFetch && body != nil && resp != nil {
                        jsWg.Add(1)
                        go func() {
                                defer jsWg.Done()
                                if verbose {
                                        scriptSrcs := extractScriptSrcs(body)
                                        mu.Lock()
                                        fmt.Fprintf(os.Stderr, "VERBOSE %s => found %d <script src> tags\n", targetURL, len(scriptSrcs))
                                        mu.Unlock()
                                }
                                jsContent = fetchJSContent(targetClient, targetURL, body, finalUA, jsMax, jsSize)
                        }()
                }

                // 1. Cookie Fingerprinting
                if resp != nil {
                        mergeTechs(techMap, detectFromCookies(resp.Cookies()))
                }

                // 2. Meta Tag Extraction
                if body != nil {
                        mergeTechs(techMap, extractMetaTechs(body))
                }

                // 3. Inline Script Analysis
                if body != nil {
                        mergeTechs(techMap, detectFromInlineScripts(body))
                }

                // 4. Title Detection (in-process, no httpx subprocess)
                if body != nil && titlePatterns != nil {
                        title := extractTitle(body)
                        if title != "" {
                                if verbose {
                                        mu.Lock()
                                        fmt.Fprintf(os.Stderr, "VERBOSE %s => Title: %s\n", targetURL, title)
                                        mu.Unlock()
                                }
                                mergeTechs(techMap, detectFromTitle(title, titlePatterns))
                        }
                }

                // 5. Favicon Hash Detection (in-process, no httpx subprocess)
                if resp != nil && favHashes != nil {
                        if hash, ok := fetchFaviconHash(targetClient, targetURL, finalUA); ok {
                                tech, found := favHashes[hash]
                                if verbose {
                                        matchStr := "No Match"
                                        if found {
                                                matchStr = fmt.Sprintf("Matched: %s", tech)
                                        }
                                        mu.Lock()
                                        fmt.Fprintf(os.Stderr, "VERBOSE %s => Favicon hash: %d (%s)\n", targetURL, hash, matchStr)
                                        mu.Unlock()
                                }
                                if found {
                                        techMap[tech] = struct{}{}
                                }
                        }
                }

                // 6. Error Page Signatures
                if resp != nil {
                        mergeTechs(techMap, detectFromErrorPage(resp.Header, body))
                }

                // 7. Wait for JS content, then run single wappalyzer fingerprint
                jsWg.Wait()

                if resp != nil {
                        fingerBody := body
                        if len(jsContent) > 0 {
                                if verbose {
                                        mu.Lock()
                                        fmt.Fprintf(os.Stderr, "VERBOSE %s => fetched %d bytes of JS content\n", targetURL, len(jsContent))
                                        mu.Unlock()
                                }
                                fingerBody = make([]byte, len(body)+len(jsContent))
                                copy(fingerBody, body)
                                copy(fingerBody[len(body):], jsContent)
                        }
                        mergeTechs(techMap, wClient.Fingerprint(resp.Header, fingerBody))
                }

                // 8. Wayback Machine fallback
                shouldWayback := false
                if resp == nil {
                        shouldWayback = true
                        if verbose {
                                mu.Lock()
                                fmt.Fprintf(os.Stderr, "WARNING %s => No response, trying Wayback Machine cache...\n", targetURL)
                                mu.Unlock()
                        }
                } else if resp.StatusCode >= 403 {
                        shouldWayback = true
                        if verbose {
                                mu.Lock()
                                fmt.Fprintf(os.Stderr, "WARNING %s => HTTP %d, trying Wayback Machine cache...\n", targetURL, resp.StatusCode)
                                mu.Unlock()
                        }
                }

                if !shouldWayback && resp != nil && resp.StatusCode == 200 {
                        title := extractTitle(body)
                        lowTech := len(techMap) <= 1
                        blockKeywords := []string{"forbidden", "unauthorized", "access denied", "blocked", "restricted", "security challenge", "cloudflare", "waf"}
                        isBlockPage := false
                        lowerTitle := strings.ToLower(title)
                        for _, kw := range blockKeywords {
                                if strings.Contains(lowerTitle, kw) {
                                        isBlockPage = true
                                        break
                                }
                        }
                        if isBlockPage || (len(body) < 300 && lowTech) {
                                shouldWayback = true
                                if verbose {
                                        mu.Lock()
                                        reason := "block/WAF page"
                                        if !isBlockPage {
                                                reason = "suspiciously small response"
                                        }
                                        fmt.Fprintf(os.Stderr, "WARNING %s => Detection looks like a %s (%s), trying Wayback Machine...\n", targetURL, reason, title)
                                        mu.Unlock()
                                }
                        }
                }

                if shouldWayback {
                        _, cachedBody := fetchWaybackPage(targetClient, targetURL, finalUA)
                        if len(cachedBody) > 0 {
                                if verbose {
                                        mu.Lock()
                                        fmt.Fprintf(os.Stderr, "VERBOSE %s => Wayback cache found, %d bytes\n", targetURL, len(cachedBody))
                                        mu.Unlock()
                                }
                                mergeTechs(techMap, wClient.Fingerprint(nil, cachedBody))

                                if titlePatterns != nil {
                                        title := extractTitle(cachedBody)
                                        if title != "" {
                                                if verbose {
                                                        mu.Lock()
                                                        fmt.Fprintf(os.Stderr, "VERBOSE %s => Extracted Title (Wayback): %s\n", targetURL, title)
                                                        mu.Unlock()
                                                }
                                                mergeTechs(techMap, detectFromTitle(title, titlePatterns))
                                        }
                                }

                                mergeTechs(techMap, extractMetaTechs(cachedBody))
                                mergeTechs(techMap, detectFromInlineScripts(cachedBody))

                                if jsFetch {
                                        origSrcs := extractOriginalScriptSrcs(cachedBody)
                                        if verbose {
                                                mu.Lock()
                                                fmt.Fprintf(os.Stderr, "VERBOSE %s => Wayback page has %d original <script src> tags\n", targetURL, len(origSrcs))
                                                mu.Unlock()
                                        }
                                        if len(origSrcs) > 0 {
                                                seen := make(map[string]bool)
                                                var jsURLs []string
                                                for _, src := range origSrcs {
                                                        resolved := resolveURL(targetURL, src)
                                                        if resolved == "" || seen[resolved] {
                                                                continue
                                                        }
                                                        if !strings.HasPrefix(resolved, "http://") && !strings.HasPrefix(resolved, "https://") {
                                                                continue
                                                        }
                                                        seen[resolved] = true
                                                        jsURLs = append(jsURLs, resolved)
                                                        if len(jsURLs) >= jsMax {
                                                                break
                                                        }
                                                }

                                                type result struct{ data []byte }
                                                results := make([]result, len(jsURLs))
                                                var wbJsWg sync.WaitGroup
                                                for i, jsURL := range jsURLs {
                                                        wbJsWg.Add(1)
                                                        go func(idx int, u string) {
                                                                defer wbJsWg.Done()
                                                                results[idx] = result{data: fetchPartialJS(targetClient, u, finalUA, jsSize)}
                                                        }(i, jsURL)
                                                }
                                                wbJsWg.Wait()

                                                var jsBuf []byte
                                                for _, r := range results {
                                                        if len(r.data) > 0 {
                                                                jsBuf = append(jsBuf, '\n')
                                                                jsBuf = append(jsBuf, r.data...)
                                                        }
                                                }
                                                if len(jsBuf) > 0 {
                                                        if verbose {
                                                                mu.Lock()
                                                                fmt.Fprintf(os.Stderr, "VERBOSE %s => fetched %d bytes of original JS from cached URLs\n", targetURL, len(jsBuf))
                                                                mu.Unlock()
                                                        }
                                                        augCached := append(cachedBody, jsBuf...)
                                                        mergeTechs(techMap, wClient.Fingerprint(nil, augCached))
                                                }
                                        }
                                }
                        } else if verbose {
                                mu.Lock()
                                fmt.Fprintf(os.Stderr, "VERBOSE %s => no Wayback cache available\n", targetURL)
                                mu.Unlock()
                        }
                }

                processTechOutput(targetURL, techMap)
        }
        processTarget := func(target string) {
                defer wg.Done()
                defer func() { <-sem }()

                target = normalizeInput(target)
                if target == "" {
                        return
                }

                // Per-target cookie jar to prevent cookie leakage between targets
                targetJar, _ := cookiejar.New(nil)
                targetClient := &http.Client{
                        Timeout:   time.Duration(timeoutSec) * time.Second,
                        Transport: transport,
                        Jar:       targetJar,
                }

                // Headless Mode
                if headless {
                        opts := append(chromedp.DefaultExecAllocatorOptions[:],
                                chromedp.Flag("headless", true), // true is safer compat than "new"
                                chromedp.Flag("disable-gpu", true),
                                chromedp.Flag("no-sandbox", true),
                                chromedp.Flag("disable-setuid-sandbox", true),
                                chromedp.Flag("disable-dev-shm-usage", true),
                                chromedp.Flag("disable-software-rasterizer", true),
                                chromedp.Flag("ignore-certificate-errors", true),
                        )

                        allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
                        defer allocCancel()

                        ctx, cancel := chromedp.NewContext(allocCtx)
                        defer cancel()

                        // Add timeout
                        ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
                        defer cancel()

                        var finalURL string
                        var htmlBody string
                        var cookieStr string

                        // Run chromedp
                        err := chromedp.Run(ctx,
                                chromedp.Navigate(target),
                                chromedp.WaitVisible("body", chromedp.ByQuery),
                                chromedp.OuterHTML("html", &htmlBody),
                                chromedp.Evaluate("document.cookie", &cookieStr),
                                chromedp.Location(&finalURL),
                        )

                        if err != nil {
// Downgraded to WARNING because fallback detection continues
if verbose {
mu.Lock()
fmt.Fprintf(os.Stderr, "WARNING %s => Headless failed (fallback to standard): %v\n", target, err)
mu.Unlock()
}

                                // Fallback to normal execution continues below
                        } else {
                                // Success - fingerprint and return
                                if verbose {
                                        mu.Lock()
                                        fmt.Fprintf(os.Stderr, "VERBOSE %s => Headless browser (chromedp) rendered page successfully\n", target)
                                        mu.Unlock()
                                }
                                dummyResp := &http.Response{
                                        StatusCode: 200,
                                        Header:     make(http.Header),
                                        Request:    &http.Request{URL: &url.URL{Scheme: "http", Host: target}},
                                }
                                if finalURL != "" {
                                        if u, err := url.Parse(finalURL); err == nil {
                                                dummyResp.Request.URL = u
                                        }
                                }
                                if cookieStr != "" {
                                        parts := strings.Split(cookieStr, ";")
                                        for _, part := range parts {
                                                dummyResp.Header.Add("Set-Cookie", strings.TrimSpace(part))
                                        }
                                }

                                fingerprintTarget(finalURL, targetClient, dummyResp, []byte(htmlBody))
                                return
                        }
                }

                // Full URL
                if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
                        resp, body, err := tryRequest(targetClient, target, retries, finalUA)
                        if err != nil {
                                printError(target, err)
                                fingerprintTarget(target, targetClient, nil, nil)
                                return
                        }

                        fingerprintTarget(target, targetClient, resp, body)
                        return
                }

                // Try HTTPS
                httpsURL := "https://" + target
                resp, body, err := tryRequest(targetClient, httpsURL, retries, finalUA)

                // fallback HTTP
                if err != nil {
                        httpURL := "http://" + target
                        resp, body, err = tryRequest(targetClient, httpURL, retries, finalUA)
                        if err != nil {
                                printError(httpsURL, err)
                                fingerprintTarget(httpsURL, targetClient, nil, nil)
                                return
                        }

                        fingerprintTarget(httpURL, targetClient, resp, body)
                        return
                }

                fingerprintTarget(httpsURL, targetClient, resp, body)
        }

        queueTarget := func(line string) {
                if rateLimiter != nil {
                        <-rateLimiter
                }
                wg.Add(1)
                sem <- struct{}{}
                go processTarget(line)
        }

        // Single
        if singleURL != "" {
                queueTarget(singleURL)
                wg.Wait()
                return
        }

        // File
        if listFile != "" {
                file, err := os.Open(listFile)
                if err != nil {
                        fmt.Println("Error opening file:", err)
                        return
                }
                defer file.Close()

                scanner := bufio.NewScanner(file)
                for scanner.Scan() {
                        queueTarget(scanner.Text())
                }

                wg.Wait()
                return
        }

        // stdin
        stat, _ := os.Stdin.Stat()
        if (stat.Mode() & os.ModeCharDevice) == 0 {
                scanner := bufio.NewScanner(os.Stdin)
                for scanner.Scan() {
                        queueTarget(scanner.Text())
                }

                wg.Wait()
                return
        }

        fmt.Println("Usage:")
        fmt.Println("  wappscan -u example.com")
        fmt.Println("  wappscan -l subs.txt")
        fmt.Println("  cat subs.txt | wappscan")
        fmt.Println("Options:")
        flag.PrintDefaults()
}