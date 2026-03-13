# ssh_parallel

> **Note:** This tool was built entirely as a test of [Claude Code](https://claude.ai/claude-code) capabilities — from initial implementation through iterative feature additions, all code was written by Claude Code with minimal human intervention.

A command-line tool for running SSH commands and transferring files across multiple hosts in parallel, with support for DNS zone files, regex filtering, live dashboards, and rich output formatting.

---

## Features

- Run shell commands on many hosts simultaneously
- Upload or download files to/from all hosts in parallel
- Load hosts from a list, a file, or a DNS zone file
- Filter hosts with a regular expression (with confirmation prompt)
- Live updating dashboard with per-host status and timing
- Automatic FQDN resolution from zone files
- Categorised SSH error reporting
- Per-run statistics: total, success, failures, average and total time

---

## Installation

```bash
make
```

Requires Go and `ssh`/`scp` available in `$PATH`.

---

## Usage

```
ssh_parallel [options] <command>
ssh_parallel [options] --upload <local_file> <remote_path>
ssh_parallel [options] --download <remote_file>
```

---

## Options

### Host Selection

| Flag | Description |
|------|-------------|
| `-H, --hosts <h1,h2,...>` | Comma-separated list of hostnames |
| `-f, --hosts-file <file>` | Plain text file, one hostname per line (`#` comments allowed) |
| `-z, --zone-file <file>` | DNS zone file; hosts taken from A/AAAA records |

When a zone file with a `$ORIGIN` directive is used, bare hostnames are automatically expanded to FQDNs. If `$ORIGIN` is absent, the domain is inferred from the filename (e.g. `example.com.zone` → `example.com`).

### Filtering

| Flag | Description |
|------|-------------|
| `-F, --filter <regex>` | Only target hosts matching the regular expression |

When a filter is used the tool shows the matched hosts and the operation to be performed, and requires confirmation before proceeding.

### Execution

| Flag | Description |
|------|-------------|
| `--dry-run` | Print what would run on which hosts without executing anything |
| `--timeout <seconds>` | Per-host timeout in seconds (default: `30`) |
| `--strict-host-key` | Reject unknown host keys instead of auto-accepting |

### File Transfer

| Flag | Description |
|------|-------------|
| `--upload <local_file>` | Upload a local file to all hosts; remote path is the next argument |
| `--download <remote_file>` | Download a file from all hosts |
| `--dest <dir>` | Parent directory for the download folder (default: `.`) |

Downloaded files are saved into an automatically created directory named `download_<filename>` (e.g. downloading `/var/log/app.log` creates `./download_app.log/`). Each file inside is named `<shortname>_<filename>` (e.g. `web1_app.log`).

### Output

| Flag | Description |
|------|-------------|
| `-s, --short` | Compact single-line output per host |
| `-D, --dashboard` | Live updating table during execution |

---

## Output Modes

### Standard (default)

Shows a `[N/total]` progress counter while running, then prints each host with colour-coded status, output lines, and a summary:

```
web1  [OK]
  14:02:11 up 42 days, load average: 0.01

web2  [FAIL (connection refused)]

─────────────────────────────────────
total: 2  ✓ 1  ✗ 1  avg: 0.312s  total time: 0.318s
```

### Short (`-s`)

One line per host. Successful hosts show output inline; failures show the status bracket:

```
web1: 14:02:11 up 42 days, load average: 0.01
web2  [FAIL (connection refused)]
```

### Dashboard (`-D`)

A live table that updates every 100 ms with an animated spinner, elapsed time per host, and a truncated result preview:

```
  HOST    STATUS     TIME       RESULT
  ──────────────────────────────────────────────────────
  web1    OK         0.84s      14:02:11 up 42 days...
  web2    /          1.21s
  db1     FAIL       0.31s      connection refused
```

---

## Examples

```bash
# Run uptime on three hosts
ssh_parallel -H web1,web2,web3 uptime

# Run a command on all hosts in a file
ssh_parallel -f hosts.txt 'df -h'

# Use a zone file and filter to web servers, with live dashboard
ssh_parallel -z example.com.zone -F 'web.*' -D uptime

# Dry-run to preview what would execute
ssh_parallel -z example.com.zone -F 'web.*' --dry-run nginx -t

# Upload a config file to all web servers
ssh_parallel -z example.com.zone -F 'web.*' --upload ./nginx.conf /etc/nginx/nginx.conf

# Download logs from all hosts into ./download_app.log/
ssh_parallel -z example.com.zone --download /var/log/app.log

# Download logs into a specific directory
ssh_parallel -z example.com.zone --download /var/log/app.log --dest /tmp/logs
```

---

## SSH Error Classification

Connection failures are automatically categorised:

| Category | Trigger |
|----------|---------|
| DNS error | Hostname could not be resolved |
| Connection timeout | TCP connect timed out |
| Connection refused | Port closed or service not running |
| Network unreachable | No route to host |
| Permission denied | Authentication failure |
| Host key mismatch | Known-hosts conflict |
| Connection reset | Connection dropped mid-session |
