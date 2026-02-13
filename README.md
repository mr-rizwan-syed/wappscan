<p align="center">
  <h1 align="center">wappscan</h1>
  <p align="center">Fast, in-process web technology fingerprinting tool written in Go</p>
</p>

<p align="center">
  <a href="#installation">Install</a> •
  <a href="#features">Features</a> •
  <a href="#usage">Usage</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#why-wappscan">Why Wappscan</a>
</p>

---

## Why Wappscan?

Most technology fingerprinting tools rely on a **single detection method** — typically just HTTP headers and HTML body analysis. `wappscan` goes much further by combining **8 distinct detection techniques** into a single tool, providing significantly richer results than any individual method.

### Comparison with Other Tools

| Feature | wappscan | httpx -td | webanalyze | whatweb |
|---|:---:|:---:|:---:|:---:|
| Header + Body fingerprinting | ✅ | ✅ | ✅ | ✅ |
| Cookie-based detection | ✅ | ❌ | ❌ | ✅ |
| Favicon hash matching | ✅ | ✅ | ❌ | ❌ |
| Page title pattern matching | ✅ | ❌ | ❌ | ❌ |
| Inline script analysis | ✅ | ❌ | ❌ | ❌ |
| External JS file inspection | ✅ | ❌ | ❌ | ❌ |
| Meta tag parsing | ✅ | ❌ | ❌ | ✅ |
| Error page signatures | ✅ | ❌ | ❌ | ❌ |
| Wayback Machine fallback | ✅ | ❌ | ❌ | ❌ |
| Headless Chrome mode | ✅ | ❌ | ❌ | ❌ |
| In-process (no subprocess) | ✅ | N/A | ✅ | ✅ |
| Proxy support | ✅ | ✅ | ❌ | ✅ |
| Self-update | ✅ | ✅ | ❌ | ❌ |
| JSON output | ✅ | ✅ | ✅ | ✅ |

### Combining with httpx -td

`wappscan` is designed to be used alongside `httpx -td` for **maximum coverage**. Each tool detects technologies the other misses:

```bash
# Full pipeline: subdomain discovery → HTTP probe → deep fingerprinting
subfinder -d target.com | httpx -o urls.txt
cat urls.txt | wappscan -json -o wappscan_results.json

# Or combine httpx tech detection with wappscan for maximum coverage
echo "https://target.com" | httpx -td -json | jq -r '.url' | wappscan
```

**Why both?** `httpx -td` uses Wappalyzer signatures on headers+body (fast, lightweight), while `wappscan` adds cookie analysis, JS file inspection, favicon hashing, error page detection, title pattern matching, and Wayback Machine fallback. Together they provide the most comprehensive technology fingerprint available.

---

## Features

- **8-source detection pipeline**: Headers, body, cookies, meta tags, inline scripts, external JS, favicon hashes, title patterns
- **In-process favicon hashing**: No external dependencies — uses murmur3 hashing directly
- **JavaScript analysis**: Fetches and inspects external JS files for framework signatures
- **Wayback Machine fallback**: Falls back to archived versions for blocked/minimal pages
- **Headless Chrome**: Optional browser mode for JS-rendered / WAF-protected sites
- **Proxy support**: HTTP/SOCKS5 proxy for all requests
- **Self-update**: Update to latest version with `-update`
- **Rate limiting**: Control request rate with `-rate-limit`
- **Concurrent scanning**: Process multiple targets simultaneously
- **Auto-download data files**: Downloads databases to `~/.config/wappscan/` on first run
- **Multiple output formats**: Plaintext (colored) and JSON (`webanalyze`-compatible)

---

## Installation

```bash
go install github.com/mr-rizwan-syed/wappscan@latest
```

Data files (`favicon_hashes.csv`, `title_patterns.csv`) are **automatically downloaded** to `~/.config/wappscan/` on first run.

### Update

```bash
wappscan -update
```

### Headless Mode (Optional)

If you need `-headless` capabilities (WAF bypass, JS rendering) on **Kali Linux / WSL**:

```bash
sudo apt update && sudo apt install -y chromium
```

wappscan will automatically disable headless mode (and warn you) if Chrome is missing, so installation is optional.
---

## Usage

```bash
# Single target
wappscan -u https://example.com

# Multiple targets from file
wappscan -l urls.txt

# Pipeline from stdin
cat urls.txt | wappscan

# JSON output (webanalyze-compatible)
wappscan -u https://example.com -json

# Through a proxy (Burp Suite)
wappscan -u https://example.com -proxy http://127.0.0.1:8080

# Rate-limited scanning (10 req/s)
wappscan -l urls.txt -rate-limit 10

# Headless Chrome mode for JS-heavy sites
wappscan -u https://spa-app.com -headless

# Verbose + output to file
wappscan -l urls.txt -v -o results.txt

# No color output (for piping)
wappscan -l urls.txt -no-color
```

---

## How It Works

`wappscan` runs a **multi-stage detection pipeline** for every target. Each stage independently identifies technologies, and results are merged for comprehensive coverage.

### Detection Pipeline

```
Target URL
    │
    ▼
┌─────────────────────────────────┐
│ 1. HTTP Request (with retries)  │──→ Response Headers + Body
└─────────────┬───────────────────┘
              │
    ┌─────────┼───────────────────────────────┐
    │         │         Parallel Detection     │
    │         ▼                                │
    │  ┌─────────────┐  ┌──────────────────┐  │
    │  │ 2. Cookies  │  │ 3. Meta Tags     │  │
    │  │   Detection │  │    (generator)   │  │
    │  └─────────────┘  └──────────────────┘  │
    │         ▼                                │
    │  ┌─────────────┐  ┌──────────────────┐  │
    │  │ 4. Inline   │  │ 5. Title Pattern │  │
    │  │   Scripts   │  │    Matching      │  │
    │  └─────────────┘  └──────────────────┘  │
    │         ▼                                │
    │  ┌─────────────┐  ┌──────────────────┐  │
    │  │ 6. Favicon  │  │ 7. Error Page    │  │
    │  │   Hash      │  │    Signatures    │  │
    │  └─────────────┘  └──────────────────┘  │
    │         ▼                                │
    │  ┌─────────────────────────────────────┐ │
    │  │ 8. External JS Fetch + Analysis     │ │
    │  │    (parallel, up to 5 files)        │ │
    │  └─────────────────────────────────────┘ │
    │         ▼                                │
    │  ┌─────────────────────────────────────┐ │
    │  │ 9. Wappalyzer Fingerprint           │ │
    │  │    (headers + body + JS content)    │ │
    │  └─────────────────────────────────────┘ │
    └──────────┬──────────────────────────────┘
               │
               ▼
    ┌──────────────────────┐
    │ Fallback: Wayback    │ ← Only if blocked/minimal/error
    │ Machine Archive      │
    └──────────────────────┘
               │
               ▼
         Merged Results
```

### Detection Methods in Detail

| # | Method | What It Detects | Example |
|---|---|---|---|
| 1 | **Cookie Analysis** | Server frameworks by cookie names | `PHPSESSID` → PHP, `laravel_session` → Laravel |
| 2 | **Meta Tags** | CMS/generators from `<meta>` tags | `<meta name="generator" content="WordPress">` |
| 3 | **Inline Scripts** | JS frameworks from `<script>` content | `__NEXT_DATA__` → Next.js + React |
| 4 | **Title Patterns** | Products by page title keywords | "Zimbra" → Zimbra, "GitLab" → GitLab |
| 5 | **Favicon Hash** | Products by favicon mmh3 hash | Hash `116323821` → Jira |
| 6 | **Error Pages** | Servers from error page signatures | "Microsoft-IIS" in headers → IIS |
| 7 | **External JS** | Libraries from JS file content | jQuery, React, Angular signatures |
| 8 | **Wappalyzer** | 2500+ technologies via signature DB | Comprehensive header + body patterns |

### Fallback Mechanism

When the primary scan produces **blocked, minimal, or error results**, `wappscan` automatically falls back to the **Wayback Machine**:

```
Primary Scan Failed?
    │
    ├── HTTP 403+ response          → Wayback fallback
    ├── No response (timeout)       → Wayback fallback
    ├── Block page detected         → Wayback fallback
    │   (title contains: forbidden,
    │    cloudflare, waf, denied)
    ├── Tiny response (<300 bytes)  → Wayback fallback
    │   + few detections (≤1)
    └── Normal response             → Use primary results
```

**Why is this useful?**

- **WAF-protected sites**: Cloudflare, Akamai, etc. often block automated tools. The Wayback cache preserves the original technology stack
- **Rate-limited targets**: When you get 429/503 responses, archived versions still provide detection
- **Decommissioned services**: Subdomains that now return errors may have cached technology data
- **Bug bounty**: Identify technologies behind WAFs without active exploitation

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `-u` | | Single target URL/domain |
| `-l` | | File containing list of URLs |
| `-c` | `20` | Concurrency level |
| `-t` | `25` | Timeout in seconds |
| `-r` | `1` | Retries for temporary errors |
| `-json` | `false` | JSON output (webanalyze-compatible) |
| `-o` | | Output file path |
| `-q` / `-silent` | `false` | Quiet/silent mode |
| `-v` | `false` | Verbose/debug mode |
| `-no-color` | `false` | Disable colored output |
| `-proxy` | | HTTP/SOCKS5 proxy URL |
| `-rate-limit` | `0` | Max requests/sec (0=unlimited) |
| `-update` | | Update to latest version |
| `-version` | | Show version |
| `-headless` | `false` | Use Headless Chrome |
| `-js-fetch` | `true` | Fetch external JS files |
| `-js-max` | `5` | Max JS files per target |
| `-js-size` | `204800` | Max bytes per JS file |
| `-k` | `true` | Skip TLS verification |
| `-ua` | | Custom User-Agent |
| `-favicon-db` | `~/.config/wappscan/...` | Favicon hash DB |
| `-title-db` | `~/.config/wappscan/...` | Title patterns DB |

---

## Use Cases

### Bug Bounty Recon
```bash
# Full subdomain → tech stack pipeline
subfinder -d target.com | httpx -o live.txt
cat live.txt | wappscan -json -o techs.json

# Filter for specific technologies (e.g., WordPress targets)
cat techs.json | jq -r 'select(.matches[].app_name == "WordPress") | .hostname'
```

### Penetration Testing
```bash
# Route through Burp Suite for manual testing
wappscan -u https://target.com -proxy http://127.0.0.1:8080 -v

# Headless mode for WAF-protected apps
wappscan -l targets.txt -headless -o results.txt
```

### Asset Inventory
```bash
# Rate-limited scan of large asset lists
wappscan -l all_assets.txt -c 50 -rate-limit 20 -json -o inventory.json
```

### CI/CD Security Checks
```bash
# Silent mode with JSON for automated processing
echo "https://staging.company.com" | wappscan -silent -json | \
  jq -r '.matches[].app_name' | sort -u
```

## Data Files

Stored in `~/.config/wappscan/` (auto-downloaded from GitHub on first run):

- **`favicon_hashes.csv`** — Maps favicon mmh3 hashes to technology names
- **`title_patterns.csv`** — Maps page title patterns to technology names

---

## Example Output

**Plaintext:**
```
wappscan v1.0.0 - Web Technology Fingerprinting Tool

https://www.example.com - [Apache, Bootstrap, Google Analytics, jQuery, PHP, WordPress]
```

**JSON:**
```json
{"hostname":"https://www.example.com","matches":[{"app_name":"Apache","version":"2.4.41"},{"app_name":"PHP","version":"7.4"},{"app_name":"WordPress","version":""}]}
```

Users install via:
```bash
go install github.com/mr-rizwan-syed/wappscan@latest
```

---

## Dependencies

| Package | Purpose |
|---|---|
| [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) | Core technology fingerprinting (2500+ signatures) |
| [chromedp](https://github.com/chromedp/chromedp) | Headless Chrome for JS-rendered pages |
| [murmur3](https://github.com/spaolacci/murmur3) | Favicon hash computation |

## Contribute 🤝

We ❤️ contributions! Help us make Wappscan better:

1.  **Add New Technologies**:
    *   Found a new favicon hash? Add it to `favicon_hashes.csv`.
    *   Found a unique title pattern? Add it to `title_patterns.csv`.
    *   Submit a Pull Request!

2.  **Report Bugs**: Open an issue if you find sites that are not detected correctly.

3.  **Improve Detection**: Suggest new ways to detect technologies (headers, cookies, etc.).

### Improvement Ideas 💡
*   [ ] Integration with Nuclei templates for vulnerability scanning
*   [ ] Automated technology crawling and hash generation
*   [ ] Docker container support
*   [ ] Community-driven signature database updates

---

## License

MIT License. See [LICENSE](../LICENSE) file.
