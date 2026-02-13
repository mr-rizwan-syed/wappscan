# wappscan

A fast, in-process web technology fingerprinting tool written in Go. Identifies technologies, frameworks, CDNs, and server software by analyzing HTTP headers, HTML content, JavaScript files, cookies, meta tags, favicons, and inline scripts.

## Features

- **Multi-source detection**: Headers, body, cookies, meta tags, inline scripts, favicon hashes, title patterns
- **In-process favicon hashing**: No external `httpx` dependency — uses murmur3 hashing directly
- **JavaScript analysis**: Fetches and inspects external JS files for framework signatures
- **Wayback Machine fallback**: Falls back to archived versions for minimal or error pages
- **Headless Chrome**: Optional headless browser mode for JS-heavy / WAF-protected sites
- **Concurrent scanning**: Process multiple targets simultaneously
- **Auto-download data files**: Downloads `favicon_hashes.csv` and `title_patterns.csv` from GitHub to `~/.config/wappscan/` on first run
- **Multiple output formats**: Plaintext and JSON (`webanalyze`-compatible)

## Dependencies

| Dependency | Purpose |
|---|---|
| [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) | Core technology fingerprinting engine |
| [chromedp](https://github.com/chromedp/chromedp) | Headless Chrome for JS-rendered pages |
| [murmur3](https://github.com/spaolacci/murmur3) | Favicon hash computation |

### Optional Runtime Dependencies

| Tool | Required For |
|---|---|
| Google Chrome / Chromium | `-headless` flag only |

## Installation

```bash
go install github.com/mr-rizwan-syed/wappscan@latest
```

Data files (`favicon_hashes.csv`, `title_patterns.csv`) are **automatically downloaded** to `~/.config/wappscan/` on first run.

## Usage

```bash
# Single target
wappscan -u https://example.com

# Multiple targets from file
wappscan -l urls.txt

# Pipe from stdin
cat urls.txt | wappscan

# JSON output
wappscan -u https://example.com -json

# Verbose + headless + output to file
wappscan -l urls.txt -headless -v -o results.txt

# With concurrency control
wappscan -l urls.txt -c 50 -t 30
```

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
| `-q` | `false` | Quiet mode |
| `-v` | `false` | Verbose/debug mode |
| `-headless` | `false` | Use Headless Chrome |
| `-js-fetch` | `true` | Fetch external JS files |
| `-js-max` | `5` | Max JS files per target |
| `-js-size` | `204800` | Max bytes per JS file |
| `-k` | `true` | Skip TLS verification |
| `-ua` | | Custom User-Agent |
| `-favicon-db` | `~/.config/wappscan/favicon_hashes.csv` | Favicon hash DB |
| `-title-db` | `~/.config/wappscan/title_patterns.csv` | Title patterns DB |

## Data Files

Stored in `~/.config/wappscan/` (auto-downloaded from GitHub on first run):

- **`favicon_hashes.csv`** — Maps favicon mmh3 hashes to technology names
- **`title_patterns.csv`** — Maps page title patterns to technology names

## Example Output

```
https://example.com - [Apache, Bootstrap, Google Analytics, jQuery, PHP, WordPress]
```

```json
{"hostname":"https://example.com","matches":[{"app_name":"Apache","version":"2.4.41"},{"app_name":"PHP","version":"7.4"}]}
```

---

## Publishing to GitHub

### 1. Create a new GitHub repository

Go to [github.com/new](https://github.com/new) and create a repo named `wappscan`.

### 2. Initialize and push

```bash
cd /path/to/chomtesh/core/wappscan

# Initialize git repo
git init
git branch -M main

# Add remote
git remote add origin https://github.com/mr-rizwan-syed/wappscan.git

# Add all files
git add wappscan.go wappscan_test.go go.mod go.sum favicon_hashes.csv title_patterns.csv README.md .gitignore

# Commit and push
git commit -m "Initial release: wappscan - web technology fingerprinting tool"
git push -u origin main
```

### 3. Create a release tag (for `go install`)

```bash
git tag v1.0.0
git push origin v1.0.0
```

### 4. Users can now install via

```bash
go install github.com/mr-rizwan-syed/wappscan@latest
```

### 5. Keep data files in the repo root

The CSV files (`favicon_hashes.csv`, `title_patterns.csv`) **must stay in the repo root** — the auto-download logic fetches them from `raw.githubusercontent.com/mr-rizwan-syed/wappscan/main/`.

## Running Tests

```bash
go test -v ./...
```

## License

See [LICENSE](../LICENSE) file.
