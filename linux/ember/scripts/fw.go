package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

type Proto int

const (
	ProtoTCP Proto = iota
	ProtoUDP
	ProtoICMP
	ProtoUnknown
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	case ProtoICMP:
		return "ICMP"
	default:
		return "UNK"
	}
}

type Line struct {
	Prefix     string
	Protocol   Proto
	Source     string
	Dest       string
	SourcePort string
	DestPort   string
	Timestamp  time.Time
}

type LineKey struct {
	Protocol Proto
	Source   string
	Dest     string
	DestPort string
}

var (
	keyvalR  = regexp.MustCompile(`\b([A-Z]+)=([^ \n]+)`)
	prefixR  = regexp.MustCompile(`\[([^\]]+)\]\s+IN=`)
	dmesgTsR = regexp.MustCompile(`^\[([^\]]+)\]`)
)

type ParserFunc func(string) (time.Time, error)

func parseRFC3339(line string) (time.Time, error) {
	fields := strings.Fields(line)
	if len(fields) > 0 {
		if t, err := time.Parse(time.RFC3339, fields[0]); err == nil {
			return t, nil
		}
		if t, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
			return t, nil
		}
		if len(fields) > 1 {
			combined := fields[0] + " " + fields[1]
			if t, err := time.ParseInLocation("2006-01-02 15:04:05", combined, time.Local); err == nil {
				return t, nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("failed to parse RFC3339 timestamp")
}

func parseDmesg(line string) (time.Time, error) {
	if m := dmesgTsR.FindStringSubmatch(line); len(m) > 1 {
		layout := "Mon Jan _2 15:04:05 2006"
		if t, err := time.ParseInLocation(layout, m[1], time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("failed to parse Dmesg timestamp")
}

func parseLegacySyslog(line string) (time.Time, error) {
	if len(line) > 15 {
		tsStr := line[:15]
		now := time.Now()
		if t, err := time.ParseInLocation(time.Stamp, tsStr, time.Local); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(48 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("failed to parse Legacy Syslog timestamp")
}

func detectParser(firstLine string) ParserFunc {
	if _, err := parseRFC3339(firstLine); err == nil {
		return parseRFC3339
	}

	if _, err := parseDmesg(firstLine); err == nil {
		return parseDmesg
	}

	if _, err := parseLegacySyslog(firstLine); err == nil {
		return parseLegacySyslog
	}

	return nil
}

func parseFields(line string) map[string]string {
	fields := make(map[string]string)
	matches := keyvalR.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		fields[match[1]] = match[2]
	}
	return fields
}

func parseLine(line string, tsParser ParserFunc) (*Line, error) {
	fields := parseFields(line)
	if len(fields) == 0 {
		return nil, nil
	}

	prefixMatches := prefixR.FindAllStringSubmatch(line, -1)
	prefix := ""
	if len(prefixMatches) > 0 {
		prefix = prefixMatches[len(prefixMatches)-1][1]
	}

	src, okSrc := fields["SRC"]
	dst, okDst := fields["DST"]
	protoStr, okProto := fields["PROTO"]

	if !okSrc || !okDst || !okProto {
		return nil, nil
	}

	proto := ProtoUnknown
	switch protoStr {
	case "TCP":
		proto = ProtoTCP
	case "UDP":
		proto = ProtoUDP
	case "ICMP":
		proto = ProtoICMP
	}

	ts := time.Time{}
	if tsParser != nil {
		var err error
		ts, err = tsParser(line)
		if err != nil {
			return nil, err
		}
	}

	l := &Line{
		Prefix:    prefix,
		Protocol:  proto,
		Source:    src,
		Dest:      dst,
		Timestamp: ts,
	}

	if proto == ProtoTCP || proto == ProtoUDP {
		l.SourcePort = fields["SPT"]
		l.DestPort = fields["DPT"]
	}

	return l, nil
}

type StringSliceFlag []string

func (s *StringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *StringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	var filePaths StringSliceFlag
	flag.Var(&filePaths, "f", "Log file to parse (can be repeated). Use '-' for stdin.")

	var sinceStr string
	flag.StringVar(&sinceStr, "since", "", "Filter logs since duration (e.g. 5m, 1h)")
	flag.StringVar(&sinceStr, "s", "", "Filter logs since duration (shorthand)")

	var protoFilter string
	flag.StringVar(&protoFilter, "proto", "", "Filter by protocol (TCP, UDP, ICMP)")
	flag.StringVar(&protoFilter, "p", "", "Filter by protocol (shorthand)")

	flag.Parse()

	var cutoffTime time.Time
	if sinceStr != "" {
		d, err := time.ParseDuration(sinceStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid duration format: %v\n", err)
			os.Exit(1)
		}
		cutoffTime = time.Now().Add(-d)
	}

	var targetProto Proto = ProtoUnknown
	if protoFilter != "" {
		switch strings.ToUpper(protoFilter) {
		case "TCP":
			targetProto = ProtoTCP
		case "UDP":
			targetProto = ProtoUDP
		case "ICMP":
			targetProto = ProtoICMP
		default:
			fmt.Fprintf(os.Stderr, "Invalid protocol: %s\n", protoFilter)
			os.Exit(1)
		}
	}

	prefixes := make(map[string]map[LineKey]int)

	inputs := []struct {
		r    io.Reader
		name string
	}{}

	stdinInfo, _ := os.Stdin.Stat()
	isPiped := (stdinInfo.Mode() & os.ModeCharDevice) == 0

	if isPiped && len(filePaths) == 0 {
		inputs = append(inputs, struct {
			r    io.Reader
			name string
		}{os.Stdin, "stdin"})
	} else if len(filePaths) > 0 {
		for _, path := range filePaths {
			if path == "-" {
				inputs = append(inputs, struct {
					r    io.Reader
					name string
				}{os.Stdin, "stdin"})
			} else {
				f, err := os.Open(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error opening %s: %v\n", path, err)
					continue
				}
				defer f.Close()
				inputs = append(inputs, struct {
					r    io.Reader
					name string
				}{f, path})
			}
		}
	} else {
		candidates := []string{"/var/log/kern.log", "/var/log/messages", "/var/log/syslog"}
		found := false
		for _, path := range candidates {
			if _, err := os.Stat(path); err == nil {
				fmt.Fprintf(os.Stderr, "Reading from %s\n", path)
				f, err := os.Open(path)
				if err == nil {
					defer f.Close()
					inputs = append(inputs, struct {
						r    io.Reader
						name string
					}{f, path})
					found = true
					break
				}
			}
		}

		if !found {
			cmd := exec.Command("journalctl", "-k", "--no-pager")
			if err := cmd.Start(); err == nil {
				path, err := exec.LookPath("journalctl")
				if err == nil {
					fmt.Fprintf(os.Stderr, "Reading from journalctl (%s)\n", path)
					stdout, _ := cmd.StdoutPipe()
					if err := cmd.Start(); err == nil {
						inputs = append(inputs, struct {
							r    io.Reader
							name string
						}{stdout, "journalctl"})
						found = true
					}
				}
			}
		}

		if !found {
			fmt.Fprintln(os.Stderr, "No standard log files found. Running 'dmesg -T'...")
			cmd := exec.Command("dmesg", "-T")
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to pipe dmesg: %v\n", err)
				os.Exit(1)
			}
			if err := cmd.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to start dmesg: %v\n", err)
				os.Exit(1)
			}
			inputs = append(inputs, struct {
				r    io.Reader
				name string
			}{stdout, "dmesg"})
		}
	}

	for _, input := range inputs {
		scanner := bufio.NewScanner(input.r)
		if !scanner.Scan() {
			continue
		}

		firstLine := scanner.Text()
		parser := detectParser(firstLine)

		if parser == nil {
			fmt.Fprintf(os.Stderr, "Skipping input %s: unknown timestamp format (first line: %.50s...)\n", input.name, firstLine)
			continue
		}

		process := func(l *Line) {
			if !cutoffTime.IsZero() && !l.Timestamp.IsZero() {
				if l.Timestamp.Before(cutoffTime) {
					return
				}
			}

			if protoFilter != "" && l.Protocol != targetProto {
				return
			}

			key := LineKey{
				Protocol: l.Protocol,
				Source:   l.Source,
				Dest:     l.Dest,
				DestPort: l.DestPort,
			}

			if prefixes[l.Prefix] == nil {
				prefixes[l.Prefix] = make(map[LineKey]int)
			}
			prefixes[l.Prefix][key]++
		}

		if line, err := parseLine(firstLine, parser); err == nil && line != nil {
			process(line)
		}

		for scanner.Scan() {
			lineText := scanner.Text()
			line, err := parseLine(lineText, parser)
			if err != nil || line == nil {
				continue
			}
			process(line)
		}
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	var sortedPrefixes []string
	for p := range prefixes {
		sortedPrefixes = append(sortedPrefixes, p)
	}
	sort.Strings(sortedPrefixes)

	for _, prefix := range sortedPrefixes {
		counts := prefixes[prefix]

		type keyVal struct {
			key LineKey
			val int
		}
		sorted := []keyVal{}
		for k, v := range counts {
			sorted = append(sorted, keyVal{k, v})
		}

		slices.SortFunc(sorted, func(a, b keyVal) int {
			if a.key.Protocol != b.key.Protocol {
				return int(a.key.Protocol) - int(b.key.Protocol)
			}
			return b.val - a.val
		})

		for _, pair := range sorted {
			l := pair.key
			count := pair.val

			protoFmt := l.Protocol.String()
			srcFmt := l.Source
			dstFmt := l.Dest

			if l.Protocol == ProtoTCP || l.Protocol == ProtoUDP {
				dstFmt = fmt.Sprintf("%s:%s", l.Dest, l.DestPort)
			}

			fmt.Fprintf(writer, "%s\t%s\t%s -> %s\t(%d)\n", prefix, protoFmt, srcFmt, dstFmt, count)
		}
	}
	writer.Flush()
}
