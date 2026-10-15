// Command livetable prints one table from the files of a live load run in
// DIR: <scenario>.load.json from the load tool and <scenario>.tail.sum.json
// from tailsum.
//
//	livetable DIR
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type loadResult struct {
	Seconds float64 `json:"seconds"`
	Kinds   []struct {
		Kind      string         `json:"kind"`
		OK        int            `json:"ok"`
		Errors    map[string]int `json:"errors"`
		P50       float64        `json:"p50_ms"`
		P95       float64        `json:"p95_ms"`
		P99       float64        `json:"p99_ms"`
		Max       float64        `json:"max_ms"`
		MiBPerSec float64        `json:"mib_per_s"`
	} `json:"kinds"`
}

type tailSum struct {
	DOEvents     int            `json:"do_events"`
	DOCPUTotal   float64        `json:"do_cpu_total_ms"`
	DOCPUp99     float64        `json:"do_cpu_p99_ms"`
	MemoryMaxMiB float64        `json:"memory_max_mib"`
	DOStarts     int            `json:"do_starts"`
	Outcomes     map[string]int `json:"outcomes"`
	Exceptions   map[string]int `json:"exceptions"`
}

// mainKind is the kind of request each scenario is about.
var mainKind = map[string]string{
	"small": "small", "page": "page-load", "bulk": "download-10m",
	"upload": "upload-5m", "stream": "stream-gap", "mix": "small",
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: livetable DIR")
	}
	dir := os.Args[1]
	files, _ := filepath.Glob(filepath.Join(dir, "*.load.json"))
	var scenarios []string
	for _, f := range files {
		scenarios = append(scenarios, strings.TrimSuffix(filepath.Base(f), ".load.json"))
	}
	order := []string{"small", "page", "bulk", "upload", "stream", "mix"}
	slices.SortFunc(scenarios, func(a, b string) int { return slices.Index(order, a) - slices.Index(order, b) })

	fmt.Printf("%-8s %-24s %12s\n", "scenario", "metric", "value")
	for _, sc := range scenarios {
		rows := map[string]string{}
		var names []string
		set := func(name, v string) {
			if _, ok := rows[name]; !ok {
				names = append(names, name)
			}
			rows[name] = v
		}
		var l loadResult
		var t tailSum
		readJSON(filepath.Join(dir, sc+".load.json"), &l)
		readJSON(filepath.Join(dir, sc+".tail.sum.json"), &t)
		ok, errs := 0, 0
		var mib float64
		for _, k := range l.Kinds {
			ok += k.OK
			for _, n := range k.Errors {
				errs += n
			}
			mib += k.MiBPerSec
			if k.Kind == mainKind[sc] {
				set(k.Kind+" p50/p95/p99 ms", fmt.Sprintf("%.0f/%.0f/%.0f", k.P50, k.P95, k.P99))
				set(k.Kind+" max ms", fmt.Sprintf("%.0f", k.Max))
			}
			if k.Kind == "canary" {
				set("canary p50/p95 ms", fmt.Sprintf("%.0f/%.0f", k.P50, k.P95))
			}
		}
		set("requests ok", fmt.Sprint(ok))
		set("errors", fmt.Sprint(errs))
		set("MiB/s", fmt.Sprintf("%.2f", mib))
		set("DO cpu ms total", fmt.Sprintf("%.0f", t.DOCPUTotal))
		if ok > 0 {
			set("DO cpu ms per request", fmt.Sprintf("%.2f", t.DOCPUTotal/float64(ok)))
		}
		if mib > 0 && l.Seconds > 0 {
			set("DO cpu ms per MiB", fmt.Sprintf("%.1f", t.DOCPUTotal/(mib*l.Seconds)))
		}
		set("linear memory max MiB", fmt.Sprintf("%.1f", t.MemoryMaxMiB))
		set("DO starts", fmt.Sprint(t.DOStarts))
		exc := 0
		for _, n := range t.Exceptions {
			exc += n
		}
		set("exceptions", fmt.Sprint(exc))
		for i, name := range names {
			label := ""
			if i == 0 {
				label = sc
			}
			fmt.Printf("%-8s %-24s %12s\n", label, name, or(rows[name]))
		}
	}
}

func readJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	json.Unmarshal(b, v)
}

func or(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
