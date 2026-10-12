// Command table reads `go test -json` output for one or more runs and
// prints one row per test with its result in each run.
//
//	table go=go.json
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

type event struct {
	Action  string
	Test    string
	Elapsed float64
}

func main() {
	var hubs []string
	results := map[string]map[string]string{}
	for _, arg := range os.Args[1:] {
		hub, path, ok := strings.Cut(arg, "=")
		if !ok {
			log.Fatalf("argument %q, want name=file.json", arg)
		}
		hubs = append(hubs, hub)
		f, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 1<<20), 1<<20)
		for s.Scan() {
			var e event
			if json.Unmarshal(s.Bytes(), &e) != nil || e.Test == "" {
				continue
			}
			switch e.Action {
			case "pass", "fail", "skip":
				if results[e.Test] == nil {
					results[e.Test] = map[string]string{}
				}
				results[e.Test][hub] = fmt.Sprintf("%s %.1fs", e.Action, e.Elapsed)
			}
		}
		f.Close()
	}
	tests := make([]string, 0, len(results))
	width := len("test")
	for t := range results {
		tests = append(tests, t)
		width = max(width, len(t))
	}
	sort.Strings(tests)
	fmt.Printf("%-*s", width, "test")
	for _, h := range hubs {
		fmt.Printf("  %-10s", h)
	}
	fmt.Println()
	for _, t := range tests {
		fmt.Printf("%-*s", width, t)
		for _, h := range hubs {
			r := results[t][h]
			if r == "" {
				r = "-"
			}
			fmt.Printf("  %-10s", r)
		}
		fmt.Println()
	}
}
