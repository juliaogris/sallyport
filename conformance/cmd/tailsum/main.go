// Command tailsum summarizes the output of `wrangler tail --format json`
// for a hub: events by kind and outcome, CPU and wall time of the Durable
// Object events, exceptions, Durable Object starts, and the memory the
// hub's heartbeat logs.
//
//	tailsum -json out.json tail.json
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type event struct {
	Outcome        string  `json:"outcome"`
	ExecutionModel string  `json:"executionModel"`
	CPUTime        float64 `json:"cpuTime"`
	WallTime       float64 `json:"wallTime"`
	Exceptions     []struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"exceptions"`
	Logs []struct {
		Message []any `json:"message"`
	} `json:"logs"`
}

// Summary is what tailsum prints and writes. Times are in milliseconds.
type Summary struct {
	Events        int            `json:"events"`
	Outcomes      map[string]int `json:"outcomes"`
	DOEvents      int            `json:"do_events"`
	DOCPUTotal    float64        `json:"do_cpu_total_ms"`
	DOCPUp50      float64        `json:"do_cpu_p50_ms"`
	DOCPUp99      float64        `json:"do_cpu_p99_ms"`
	DOCPUMax      float64        `json:"do_cpu_max_ms"`
	WorkerCPU     float64        `json:"worker_cpu_total_ms"`
	Exceptions    map[string]int `json:"exceptions,omitempty"`
	DOStarts      int            `json:"do_starts"`
	MemoryMiB     []float64      `json:"memory_mib"`
	MemoryMaxMiB  float64        `json:"memory_max_mib"`
	GoHeapMaxMiB  float64        `json:"go_heap_max_mib,omitempty"`
	Goroutines    []int          `json:"goroutines,omitempty"`
	HeartbeatLogs int            `json:"heartbeats"`
}

var (
	// The wasm linear memory, which counts against the 128 MB limit. The
	// Go hub logs "linear 47.25 MiB" and the Rust hub "memory 3 MiB".
	memRE       = regexp.MustCompile(`(?:linear|memory) ([0-9.]+) ?MiB`)
	heapRE      = regexp.MustCompile(`heap ([0-9.]+) ?MiB`)
	goroutineRE = regexp.MustCompile(`goroutines (\d+)`)
)

func main() {
	jsonOut := flag.String("json", "", "also write the summary as JSON to this file")
	flag.Parse()
	var in []byte
	var err error
	if flag.NArg() > 0 {
		in, err = os.ReadFile(flag.Arg(0))
	} else {
		in, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		log.Fatal(err)
	}
	s := Summary{Outcomes: map[string]int{}, Exceptions: map[string]int{}}
	var cpu []float64
	// wrangler prints a few lines that are not JSON between the events, so
	// each event is decoded from the next "{" at the start of a line.
	for off := 0; off < len(in); {
		i := strings.Index(string(in[off:]), "{")
		if i < 0 {
			break
		}
		off += i
		dec := json.NewDecoder(bytes.NewReader(in[off:]))
		var e event
		if err := dec.Decode(&e); err != nil {
			off++
			continue
		}
		off += int(dec.InputOffset())
		s.Events++
		s.Outcomes[e.ExecutionModel+"/"+e.Outcome]++
		if e.ExecutionModel == "durableObject" {
			s.DOEvents++
			s.DOCPUTotal += e.CPUTime
			cpu = append(cpu, e.CPUTime)
		} else {
			s.WorkerCPU += e.CPUTime
		}
		for _, x := range e.Exceptions {
			msg := x.Message
			if len(msg) > 80 {
				msg = msg[:80]
			}
			s.Exceptions[x.Name+": "+msg]++
		}
		for _, l := range e.Logs {
			var parts []string
			for _, m := range l.Message {
				parts = append(parts, fmt.Sprint(m))
			}
			line := strings.Join(parts, " ")
			if strings.Contains(line, "hub: durable object started") {
				s.DOStarts++
			}
			if !strings.Contains(line, "hub: heartbeat") {
				continue
			}
			s.HeartbeatLogs++
			if m := memRE.FindStringSubmatch(line); m != nil {
				v, _ := strconv.ParseFloat(m[1], 64)
				s.MemoryMiB = append(s.MemoryMiB, v)
				s.MemoryMaxMiB = max(s.MemoryMaxMiB, v)
			}
			if m := heapRE.FindStringSubmatch(line); m != nil {
				v, _ := strconv.ParseFloat(m[1], 64)
				s.GoHeapMaxMiB = max(s.GoHeapMaxMiB, v)
			}
			if m := goroutineRE.FindStringSubmatch(line); m != nil {
				v, _ := strconv.Atoi(m[1])
				s.Goroutines = append(s.Goroutines, v)
			}
		}
	}
	slices.Sort(cpu)
	s.DOCPUp50, s.DOCPUp99, s.DOCPUMax = pct(cpu, 50), pct(cpu, 99), pct(cpu, 100)
	if len(s.Exceptions) == 0 {
		s.Exceptions = nil
	}

	fmt.Printf("events %d, durable object %d, DO starts %d, heartbeats %d\n", s.Events, s.DOEvents, s.DOStarts, s.HeartbeatLogs)
	fmt.Printf("DO cpu ms: total %.0f, p50 %.0f, p99 %.0f, max %.0f; worker cpu total %.0f\n", s.DOCPUTotal, s.DOCPUp50, s.DOCPUp99, s.DOCPUMax, s.WorkerCPU)
	fmt.Printf("linear memory MiB max %.2f, first %v, last %v\n", s.MemoryMaxMiB, first(s.MemoryMiB), last(s.MemoryMiB))
	if len(s.Goroutines) > 0 {
		fmt.Printf("go heap MiB max %.2f, goroutines max %d, last %v\n", s.GoHeapMaxMiB, slices.Max(s.Goroutines), last(s.Goroutines))
	}
	keys := make([]string, 0, len(s.Outcomes))
	for k := range s.Outcomes {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Printf("  %s: %d\n", k, s.Outcomes[k])
	}
	for k, n := range s.Exceptions {
		fmt.Printf("  exception %d x %s\n", n, k)
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(s, "", "  ")
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

func pct(v []float64, p int) float64 {
	if len(v) == 0 {
		return 0
	}
	return v[min(len(v)-1, len(v)*p/100)]
}

func first[T any](v []T) any {
	if len(v) == 0 {
		return "-"
	}
	return v[0]
}

func last[T any](v []T) any {
	if len(v) == 0 {
		return "-"
	}
	return v[len(v)-1]
}
