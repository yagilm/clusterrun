package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
)

// monitorCmd is run on each host when --monitor is used.
// It outputs three space-separated integers: cpu% mem% disk%
const monitorCmd = `_r1=$(awk 'NR==1{s=0;for(i=2;i<=NF;i++)s+=$i;print s,$5}' /proc/stat);` +
	`sleep 0.2;` +
	`_r2=$(awk 'NR==1{s=0;for(i=2;i<=NF;i++)s+=$i;print s,$5}' /proc/stat);` +
	`cpu=$(awk -v a="$_r1" -v b="$_r2" 'BEGIN{split(a,x);split(b,y);d=y[1]-x[1];print(d>0)?int(100*(1-(y[2]-x[2])/d)):0}');` +
	`mem=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{print int((t-a)*100/t)}' /proc/meminfo);` +
	`disk=$(df / | awk 'NR==2{sub(/%/,"",$5);print $5}');` +
	`echo "$cpu $mem $disk"`

func usageColor(pct int) string {
	if pct >= 80 {
		return colorRed
	}
	if pct >= 60 {
		return colorYellow
	}
	return colorGreen
}

func usageBar(pct, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := pct * width / 100
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func parseMetrics(output string) (cpu, mem, disk int, ok bool) {
	parts := strings.Fields(output)
	if len(parts) != 3 {
		return
	}
	var err error
	if cpu, err = strconv.Atoi(parts[0]); err != nil {
		return
	}
	if mem, err = strconv.Atoi(parts[1]); err != nil {
		return
	}
	if disk, err = strconv.Atoi(parts[2]); err != nil {
		return
	}
	ok = true
	return
}

type Result struct {
	host       string
	returnCode int
	output     string
	timedOut   bool
	failReason string
	duration   time.Duration
}

func classifySSHError(stderr string) string {
	s := strings.ToLower(stderr)
	switch {
	case strings.Contains(s, "could not resolve hostname") || strings.Contains(s, "name or service not known"):
		return "DNS error"
	case strings.Contains(s, "connection timed out") || strings.Contains(s, "timed out"):
		return "connection timeout"
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "network is unreachable") || strings.Contains(s, "no route to host"):
		return "network unreachable"
	case strings.Contains(s, "permission denied"):
		return "permission denied"
	case strings.Contains(s, "host key verification failed") || strings.Contains(s, "host key"):
		return "host key mismatch"
	case strings.Contains(s, "connection reset"):
		return "connection reset"
	default:
		if stderr != "" {
			line := strings.SplitN(strings.TrimSpace(stderr), "\n", 2)[0]
			return line
		}
		return ""
	}
}

func runSCP(host, src, dst, savedAs string, scpArgs []string, timeout time.Duration, wg *sync.WaitGroup, results chan<- Result) {
	defer wg.Done()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := append(scpArgs, src, dst)
	cmd := exec.CommandContext(ctx, "scp", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		results <- Result{host: host, returnCode: -1, timedOut: true, duration: time.Since(start)}
		return
	}

	returnCode := 0
	var failReason string
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			returnCode = exitErr.ExitCode()
		} else {
			returnCode = -1
		}
		failReason = classifySSHError(stderr.String())
	}

	output := ""
	if returnCode == 0 && savedAs != "" {
		output = "saved to " + savedAs
	}

	results <- Result{host: host, returnCode: returnCode, failReason: failReason, output: output, duration: time.Since(start)}
}

func runSSH(host, command string, sshArgs []string, timeout time.Duration, wg *sync.WaitGroup, results chan<- Result) {
	defer wg.Done()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := append(sshArgs, host, command)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		results <- Result{host: host, returnCode: -1, timedOut: true, duration: time.Since(start)}
		return
	}

	returnCode := 0
	var failReason string
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			returnCode = exitErr.ExitCode()
		} else {
			returnCode = -1
		}
		failReason = classifySSHError(stderr.String())
	}

	output := strings.TrimRight(stdout.String(), "\n")

	results <- Result{
		host:       host,
		returnCode: returnCode,
		output:     output,
		failReason: failReason,
		duration:   time.Since(start),
	}
}

// parseZoneFile extracts hostnames from A and AAAA records in a DNS zone file.
// Returned names are FQDNs (trailing dot stripped) when $ORIGIN is set,
// otherwise the bare label as written in the file.
func parseZoneFile(path string) ([]string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	var hosts []string
	seen := map[string]bool{}
	var origin string // e.g. "example.com."
	var lastName string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Strip inline comments
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimRight(line, " \t")
		if line == "" {
			continue
		}

		// $ORIGIN directive
		if upper := strings.ToUpper(line); strings.HasPrefix(upper, "$ORIGIN") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				origin = fields[1]
				if !strings.HasSuffix(origin, ".") {
					origin += "."
				}
			}
			continue
		}

		// Skip other directives
		if strings.HasPrefix(line, "$") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// Determine name field: lines starting with whitespace continue the last name.
		var name string
		offset := 0
		if line[0] == ' ' || line[0] == '\t' {
			name = lastName
		} else {
			name = fields[0]
			lastName = name
			offset = 1
		}

		// Skip TTL field if present (numeric)
		remaining := fields[offset:]
		if len(remaining) > 0 {
			if _, err := fmt.Sscanf(remaining[0], "%d", new(int)); err == nil {
				remaining = remaining[1:]
			}
		}

		// Expect: [IN] <type> <rdata>
		if len(remaining) < 2 {
			continue
		}
		classOrType := strings.ToUpper(remaining[0])
		if classOrType == "IN" || classOrType == "CH" || classOrType == "HS" {
			remaining = remaining[1:]
		}
		if len(remaining) < 1 {
			continue
		}
		rrType := strings.ToUpper(remaining[0])
		if rrType != "A" && rrType != "AAAA" {
			continue
		}

		// Resolve the hostname
		hostname := name
		if hostname == "@" {
			if origin != "" {
				hostname = strings.TrimSuffix(origin, ".")
			} else {
				continue
			}
		} else if !strings.HasSuffix(hostname, ".") && origin != "" {
			// Relative label — append origin
			hostname = hostname + "." + strings.TrimSuffix(origin, ".")
		} else {
			hostname = strings.TrimSuffix(hostname, ".")
		}

		if hostname != "" && !seen[hostname] {
			seen[hostname] = true
			hosts = append(hosts, hostname)
		}
	}
	return hosts, strings.TrimSuffix(origin, "."), scanner.Err()
}

type dashEntry struct {
	name       string
	start      time.Time
	done       bool
	ok         bool
	timeout    bool
	elapsed    time.Duration
	result     string
	cmdOutput  string
	cpu        int
	mem        int
	disk       int
	hasMetrics bool
}

func printResults(allResults []Result, zoneDomain string, shortOutput, monitorMode bool, timeoutSec int) {
	for _, r := range allResults {
		var statusColor, statusLabel, statusExtra string
		if r.timedOut {
			statusColor = colorYellow
			statusLabel = "TIMEOUT"
			statusExtra = fmt.Sprintf(" (%ds)", timeoutSec)
		} else if r.returnCode != 0 {
			statusColor = colorRed
			statusLabel = "FAIL"
			if r.failReason != "" {
				statusExtra = fmt.Sprintf(" (%s)", r.failReason)
			}
		} else {
			statusColor = colorGreen
			statusLabel = "OK"
		}

		displayHost := r.host
		if zoneDomain != "" {
			displayHost = strings.TrimSuffix(r.host, "."+zoneDomain)
		}

		if shortOutput {
			var out string
			if monitorMode && r.returnCode == 0 && !r.timedOut {
				lines := strings.SplitN(r.output, "\n", 2)
				if cpu, mem, disk, ok := parseMetrics(lines[0]); ok {
					out = fmt.Sprintf("cpu:%s%d%%%s mem:%s%d%%%s disk:%s%d%%%s",
						usageColor(cpu), cpu, colorReset,
						usageColor(mem), mem, colorReset,
						usageColor(disk), disk, colorReset,
					)
				}
				if len(lines) > 1 {
					if cmdOut := strings.ReplaceAll(strings.TrimSpace(lines[1]), "\n", " | "); cmdOut != "" {
						if out != "" {
							out += "  " + cmdOut
						} else {
							out = cmdOut
						}
					}
				}
			} else {
				out = strings.ReplaceAll(strings.TrimSpace(r.output), "\n", " | ")
			}
			if out != "" {
				fmt.Printf("%s%s%s  [%s%s%s%s]: %s\n",
					colorBold+colorCyan, displayHost, colorReset,
					statusColor, statusLabel+statusExtra, colorReset, colorReset,
					out,
				)
			} else {
				fmt.Printf("%s%s%s  [%s%s%s%s]\n",
					colorBold+colorCyan, displayHost, colorReset,
					statusColor, statusLabel+statusExtra, colorReset, colorReset,
				)
			}
		} else {
			if monitorMode && r.returnCode == 0 && !r.timedOut {
				lines := strings.SplitN(r.output, "\n", 2)
				if cpu, mem, disk, ok := parseMetrics(lines[0]); ok {
					const barW = 10
					fmt.Printf("%s%s%s%s  [%s%s%s%s]  CPU %s%s%s %s%3d%%%s  MEM %s%s%s %s%3d%%%s  DISK %s%s%s %s%3d%%%s\n",
						colorBold+colorCyan, displayHost, colorReset,
						colorYellow, statusColor, statusLabel+statusExtra, colorReset, colorReset,
						usageColor(cpu), usageBar(cpu, barW), colorReset, usageColor(cpu), cpu, colorReset,
						usageColor(mem), usageBar(mem, barW), colorReset, usageColor(mem), mem, colorReset,
						usageColor(disk), usageBar(disk, barW), colorReset, usageColor(disk), disk, colorReset)
				} else {
					fmt.Printf("%s%s%s%s  [%s%s%s%s]\n",
						colorBold+colorCyan, displayHost, colorReset,
						colorYellow, statusColor, statusLabel+statusExtra, colorReset, colorReset,
					)
				}
				if len(lines) > 1 {
					for _, line := range strings.Split(strings.TrimRight(lines[1], "\n"), "\n") {
						fmt.Printf("  %s\n", line)
					}
				}
			} else {
				fmt.Printf("%s%s%s%s  [%s%s%s%s]\n",
					colorBold+colorCyan, displayHost, colorReset,
					colorYellow, statusColor, statusLabel+statusExtra, colorReset, colorReset,
				)
				for _, line := range strings.Split(r.output, "\n") {
					fmt.Printf("  %s\n", line)
				}
			}
		}
	}
}

func renderDashboard(entries []dashEntry, hostWidth, tick, linesPrinted int, monitorMode bool) int {
	spinners := []string{"|", "/", "-", "\\"}

	if linesPrinted > 0 {
		fmt.Printf("\033[%dA", linesPrinted)
	}

	n := 0
	if monitorMode {
		fmt.Printf("\r\033[K  %-*s  %-9s  %-9s  %-14s  %-14s  %-14s  %s\n",
			hostWidth, "HOST", "STATUS", "TIME", "CPU", "MEM", "DISK /", "OUTPUT")
	} else {
		fmt.Printf("\r\033[K  %-*s  %-9s  %-9s  %s\n", hostWidth, "HOST", "STATUS", "TIME", "RESULT")
	}
	fmt.Printf("\r\033[K  %s\n", strings.Repeat("─", hostWidth+65))
	n += 2

	for _, e := range entries {
		var elapsed time.Duration
		if e.done {
			elapsed = e.elapsed
		} else {
			elapsed = time.Since(e.start)
		}
		timeStr := fmt.Sprintf("%.2fs", elapsed.Seconds())

		var statusText, statusColor string
		if !e.done {
			statusText = fmt.Sprintf("%-9s", spinners[tick%len(spinners)])
			statusColor = colorCyan
		} else if e.timeout {
			statusText = fmt.Sprintf("%-9s", "TIMEOUT")
			statusColor = colorYellow
		} else if e.ok {
			statusText = fmt.Sprintf("%-9s", "OK")
			statusColor = colorGreen
		} else {
			statusText = fmt.Sprintf("%-9s", "FAIL")
			statusColor = colorRed
		}

		if monitorMode {
			var cpuCol, memCol, diskCol string
			if e.done && e.hasMetrics {
				cpuCol = fmt.Sprintf("%s%s%s %s%3d%%%s",
					usageColor(e.cpu), usageBar(e.cpu, 8), colorReset, usageColor(e.cpu), e.cpu, colorReset)
				memCol = fmt.Sprintf("%s%s%s %s%3d%%%s",
					usageColor(e.mem), usageBar(e.mem, 8), colorReset, usageColor(e.mem), e.mem, colorReset)
				diskCol = fmt.Sprintf("%s%s%s %s%3d%%%s",
					usageColor(e.disk), usageBar(e.disk, 8), colorReset, usageColor(e.disk), e.disk, colorReset)
			}
			firstLine, extraLines, _ := strings.Cut(e.cmdOutput, "\n")
			fmt.Printf("\r\033[K  %s%-*s%s  %s%s%s  %-9s  %-14s  %-14s  %-14s  %s\n",
				colorBold+colorCyan, hostWidth, e.name, colorReset,
				statusColor, statusText, colorReset,
				timeStr,
				cpuCol, memCol, diskCol,
				firstLine,
			)
			n++
			if extraLines != "" {
				for _, line := range strings.Split(extraLines, "\n") {
					fmt.Printf("\r\033[K    %s\n", line)
					n++
				}
			}
		} else {
			result := e.result
			if len(result) > 40 {
				result = result[:37] + "..."
			}
			fmt.Printf("\r\033[K  %s%-*s%s  %s%s%s  %-9s  %s\n",
				colorBold+colorCyan, hostWidth, e.name, colorReset,
				statusColor, statusText, colorReset,
				timeStr,
				result,
			)
			n++
			if _, extraLines, ok := strings.Cut(e.cmdOutput, "\n"); ok {
				for _, line := range strings.Split(extraLines, "\n") {
					fmt.Printf("\r\033[K    %s\n", line)
					n++
				}
			}
		}
	}

	return n
}

func main() {
	var hostsVal, hostsFileVal, zoneFileVal, filterVal, zoneDomain string
	var dryRun, strictHostKey, shortOutput, dashboardMode, monitorMode bool
	var timeoutSec int
	var uploadVal, downloadVal, destVal string
	flag.StringVar(&hostsVal, "H", "", "")
	flag.StringVar(&hostsVal, "hosts", "", "")
	flag.StringVar(&hostsFileVal, "f", "", "")
	flag.StringVar(&hostsFileVal, "hosts-file", "", "")
	flag.StringVar(&zoneFileVal, "z", "", "")
	flag.StringVar(&zoneFileVal, "zone-file", "", "")
	flag.StringVar(&filterVal, "F", "", "")
	flag.StringVar(&filterVal, "filter", "", "")
	flag.BoolVar(&dryRun, "dry-run", false, "")
	flag.IntVar(&timeoutSec, "timeout", 30, "")
	flag.BoolVar(&strictHostKey, "strict-host-key", false, "")
	flag.BoolVar(&shortOutput, "s", false, "")
	flag.BoolVar(&shortOutput, "short", false, "")
	flag.StringVar(&uploadVal, "upload", "", "")
	flag.StringVar(&downloadVal, "download", "", "")
	flag.StringVar(&destVal, "dest", ".", "")
	flag.BoolVar(&dashboardMode, "D", false, "")
	flag.BoolVar(&dashboardMode, "dashboard", false, "")
	flag.BoolVar(&monitorMode, "m", false, "")
	flag.BoolVar(&monitorMode, "monitor", false, "")

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: clusterrun [options] <command>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run a command in parallel over multiple SSH hosts.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  -H, --hosts <host1,host2,...>   Comma-separated list of hostnames")
		fmt.Fprintln(os.Stderr, "  -f, --hosts-file <file>         File with one hostname per line (# comments allowed)")
		fmt.Fprintln(os.Stderr, "  -z, --zone-file <file>          DNS zone file; hosts are taken from A/AAAA records")
		fmt.Fprintln(os.Stderr, "  -F, --filter <regex>            Filter hostnames by regular expression")
		fmt.Fprintln(os.Stderr, "                                  When used, prompts for confirmation before running")
		fmt.Fprintln(os.Stderr, "      --dry-run                   Print what would be run on which servers without executing")
		fmt.Fprintln(os.Stderr, "      --timeout <seconds>         Seconds to wait per server before reporting timeout (default 30)")
		fmt.Fprintln(os.Stderr, "      --strict-host-key           Reject unknown host keys instead of accepting them automatically")
		fmt.Fprintln(os.Stderr, "  -s, --short                     Compact output: single line per host")
		fmt.Fprintln(os.Stderr, "  -D, --dashboard                 Live dashboard table during execution")
		fmt.Fprintln(os.Stderr, "  -m, --monitor                   Collect CPU, memory and disk (/) usage snapshot")
		fmt.Fprintln(os.Stderr, "      --upload <local_file>        Upload file to all hosts; remote path given as argument")
		fmt.Fprintln(os.Stderr, "      --download <remote_file>     Download file from all hosts; saved as <shortname>_<file>")
		fmt.Fprintln(os.Stderr, "      --dest <dir>                 Destination directory for --download (default: .)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  clusterrun -H web1,web2,web3 uptime")
		fmt.Fprintln(os.Stderr, "  clusterrun --hosts-file hosts.txt 'df -h'")
		fmt.Fprintln(os.Stderr, "  clusterrun -z example.com.zone -F 'web.*' nginx -t")
		fmt.Fprintln(os.Stderr, "  clusterrun -z example.com.zone --upload ./app.conf /etc/app/app.conf")
		fmt.Fprintln(os.Stderr, "  clusterrun -z example.com.zone --download /var/log/app.log --dest ./logs/")
	}

	flag.Parse()

	if uploadVal != "" && downloadVal != "" {
		fmt.Fprintln(os.Stderr, "Error: --upload and --download are mutually exclusive")
		os.Exit(1)
	}

	if flag.NArg() == 0 && uploadVal == "" && downloadVal == "" && !monitorMode {
		flag.Usage()
		os.Exit(1)
	}

	var command, remotePath string
	switch {
	case monitorMode:
		if flag.NArg() > 0 {
			command = monitorCmd + "; " + strings.Join(flag.Args(), " ")
		} else {
			command = monitorCmd
		}
	case uploadVal != "":
		if flag.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "Error: --upload requires a remote destination path as argument")
			os.Exit(1)
		}
		remotePath = flag.Args()[0]
	case downloadVal == "":
		command = strings.Join(flag.Args(), " ")
	}

	var hosts []string

	if hostsVal != "" {
		for _, h := range strings.Split(hostsVal, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				hosts = append(hosts, h)
			}
		}
	}

	if hostsFileVal != "" {
		data, err := os.ReadFile(hostsFileVal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading hosts file: %v\n", err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				hosts = append(hosts, line)
			}
		}
	}

	if zoneFileVal != "" {
		zoneHosts, zd, err := parseZoneFile(zoneFileVal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading zone file: %v\n", err)
			os.Exit(1)
		}
		zoneDomain = zd
		// If the zone file has no $ORIGIN, try to infer the domain from the filename.
		// Common conventions: "example.com.zone", "example.com.db", "example.com"
		if zoneDomain == "" {
			base := zoneFileVal
			if idx := strings.LastIndex(base, "/"); idx >= 0 {
				base = base[idx+1:]
			}
			for _, ext := range []string{".zone", ".db", ".txt"} {
				if strings.HasSuffix(strings.ToLower(base), ext) {
					base = base[:len(base)-len(ext)]
					break
				}
			}
			base = strings.TrimSuffix(base, ".")
			if strings.Contains(base, ".") {
				zoneDomain = base
			}
		}
		hosts = append(hosts, zoneHosts...)
	}

	// Expand bare names to FQDNs and deduplicate when a zone domain is known.
	if zoneDomain != "" {
		seen := make(map[string]bool)
		j := 0
		for _, h := range hosts {
			if !strings.Contains(h, ".") {
				h = h + "." + zoneDomain
			}
			if !seen[h] {
				seen[h] = true
				hosts[j] = h
				j++
			}
		}
		hosts = hosts[:j]
	}

	usingRegex := filterVal != ""

	if usingRegex {
		re, err := regexp.Compile(filterVal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid filter regex: %v\n", err)
			os.Exit(1)
		}
		filtered := hosts[:0]
		for _, h := range hosts {
			if re.MatchString(h) {
				filtered = append(filtered, h)
			}
		}
		hosts = filtered
	}

	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no hosts provided. Use -H/--hosts, -f/--hosts-file, or -z/--zone-file")
		os.Exit(1)
	}

	// Helper: basename of a slash-separated path.
	pathBase := func(p string) string {
		if idx := strings.LastIndex(p, "/"); idx >= 0 {
			return p[idx+1:]
		}
		return p
	}
	dlDir := destVal + "/download_" + pathBase(downloadVal)

	if dryRun {
		switch {
		case uploadVal != "":
			fmt.Printf("Would upload: %s → <host>:%s\n", uploadVal, remotePath)
			fmt.Printf("On %d server(s):\n", len(hosts))
			for _, host := range hosts {
				fmt.Printf("  scp %s %s:%s\n", uploadVal, host, remotePath)
			}
		case downloadVal != "":
			fmt.Printf("Would download: <host>:%s → %s/<shortname>_%s\n", downloadVal, dlDir, pathBase(downloadVal))
			fmt.Printf("On %d server(s):\n", len(hosts))
			for _, host := range hosts {
				shortName := strings.TrimSuffix(host, "."+zoneDomain)
				fmt.Printf("  scp %s:%s %s/%s_%s\n", host, downloadVal, dlDir, shortName, pathBase(downloadVal))
			}
		default:
			fmt.Printf("Would run command: %s\n", command)
			fmt.Printf("On %d server(s):\n", len(hosts))
			for _, host := range hosts {
				fmt.Printf("  ssh %s %s\n", host, command)
			}
		}
		return
	}

	// When regex filter was used, show plan and require confirmation.
	if usingRegex {
		switch {
		case uploadVal != "":
			fmt.Printf("Upload: %s → <host>:%s\n", uploadVal, remotePath)
		case downloadVal != "":
			fmt.Printf("Download: <host>:%s → %s/<shortname>_%s\n", downloadVal, dlDir, pathBase(downloadVal))
		}
		fmt.Printf("Matched %d server(s):\n", len(hosts))
		for _, host := range hosts {
			fmt.Printf("  %s\n", host)
		}
		fmt.Print("\nProceed? [y/N] ")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Fprintln(os.Stderr, "Aborted.")
			os.Exit(1)
		}
	}

	hostKeyCheck := "StrictHostKeyChecking=no"
	if strictHostKey {
		hostKeyCheck = "StrictHostKeyChecking=yes"
	}
	sshArgs := []string{"-o", hostKeyCheck, "-o", "BatchMode=yes"}
	timeout := time.Duration(timeoutSec) * time.Second

	runStart := time.Now()
	results := make(chan Result, len(hosts))
	var wg sync.WaitGroup

	switch {
	case uploadVal != "":
		for _, host := range hosts {
			wg.Add(1)
			go runSCP(host, uploadVal, host+":"+remotePath, "", sshArgs, timeout, &wg, results)
		}
	case downloadVal != "":
		if err := os.MkdirAll(dlDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating download directory %s: %v\n", dlDir, err)
			os.Exit(1)
		}
		for _, host := range hosts {
			wg.Add(1)
			shortName := strings.TrimSuffix(host, "."+zoneDomain)
			localFile := dlDir + "/" + shortName + "_" + pathBase(downloadVal)
			go runSCP(host, host+":"+downloadVal, localFile, "", sshArgs, timeout, &wg, results)
		}
	default:
		for _, host := range hosts {
			wg.Add(1)
			go runSSH(host, command, sshArgs, timeout, &wg, results)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	total := len(hosts)
	var allResults []Result

	if dashboardMode {
		hostIndex := make(map[string]int, len(hosts))
		entries := make([]dashEntry, len(hosts))
		hostWidth := 4
		for i, h := range hosts {
			name := strings.TrimSuffix(h, "."+zoneDomain)
			if len(name) > hostWidth {
				hostWidth = len(name)
			}
			entries[i] = dashEntry{name: name, start: time.Now()}
			hostIndex[h] = i
		}

		var mu sync.Mutex
		tick := 0
		linesPrinted := renderDashboard(entries, hostWidth, tick, 0, monitorMode)

		ticker := time.NewTicker(100 * time.Millisecond)
		tickerDone := make(chan struct{})
		go func() {
			for {
				select {
				case <-ticker.C:
					tick++
					mu.Lock()
					linesPrinted = renderDashboard(entries, hostWidth, tick, linesPrinted, monitorMode)
					mu.Unlock()
				case <-tickerDone:
					return
				}
			}
		}()

		for r := range results {
			allResults = append(allResults, r)
			idx := hostIndex[r.host]
			mu.Lock()
			entries[idx].done = true
			entries[idx].elapsed = r.duration
			entries[idx].ok = !r.timedOut && r.returnCode == 0
			entries[idx].timeout = r.timedOut
			if r.timedOut {
				entries[idx].result = "timed out"
			} else if r.returnCode != 0 {
				entries[idx].result = r.failReason
			} else if monitorMode {
				lines := strings.SplitN(r.output, "\n", 2)
				if cpu, mem, disk, ok := parseMetrics(lines[0]); ok {
					entries[idx].cpu = cpu
					entries[idx].mem = mem
					entries[idx].disk = disk
					entries[idx].hasMetrics = true
				}
				if len(lines) > 1 {
					entries[idx].cmdOutput = strings.TrimRight(lines[1], "\n")
				}
			} else {
				entries[idx].result = strings.SplitN(r.output, "\n", 2)[0]
				entries[idx].cmdOutput = strings.TrimRight(r.output, "\n")
			}
			mu.Unlock()
		}

		ticker.Stop()
		close(tickerDone)
		mu.Lock()
		renderDashboard(entries, hostWidth, tick, linesPrinted, monitorMode)
		mu.Unlock()
	} else {
		for r := range results {
			allResults = append(allResults, r)
			fmt.Fprintf(os.Stderr, "\r[%d/%d]", len(allResults), total)
		}
		fmt.Fprint(os.Stderr, "\r        \r")
		printResults(allResults, zoneDomain, shortOutput, monitorMode, timeoutSec)
	}

	if downloadVal != "" {
		fmt.Printf("saved to %s\n", dlDir)
	}

	var totalDuration time.Duration
	success, failed := 0, 0
	for _, r := range allResults {
		totalDuration += r.duration
		if r.timedOut || r.returnCode != 0 {
			failed++
		} else {
			success++
		}
	}
	avg := time.Duration(0)
	if len(allResults) > 0 {
		avg = totalDuration / time.Duration(len(allResults))
	}
	fmt.Printf("%s―――――――――――――――――――――――――――――――――――%s\n", colorYellow, colorReset)
	fmt.Printf("total: %d  %s✓ %d%s  %s✗ %d%s  avg: %s  total time: %s\n",
		len(allResults),
		colorGreen, success, colorReset,
		colorRed, failed, colorReset,
		avg.Round(time.Millisecond),
		time.Since(runStart).Round(time.Millisecond),
	)
}
