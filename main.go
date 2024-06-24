package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"strconv"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/utils/cpuset"
)

const (
	pinModeNumericRegularExpression = `^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$`
	pinModeRegularExpression        = `^first$|^last$|` + pinModeNumericRegularExpression
	singleCPURegularExpression      = `^[0-9]+$`
	firstCPURegularExpression       = `^([0-9]+)[^0-9]`
	lastCPURegularExpression        = `[^0-9]([0-9]+)$`
)

var (
	procDirectory       = "/proc/"
	statusFile          = "status"
	procNameFilter      = flag.String("proc-name-filter", "", "filter for process names to be pinned")
	pinMode             = flag.String("pin-mode", "", "instruction for vCPU to pin to (accepted values: 'first', 'last', [0-9]+,)")
	discoveryMode       = flag.Bool("discovery-mode", false, "discovery mode will print all discovered processes that match proc-name-filter")
	tickSeconds         = flag.Int("tick-seconds", 0, "additionally run logic time based every <tick> seconds (default 0 = never)")
	pinModeRegex        = regexp.MustCompile(pinModeRegularExpression)
	pinModeNumericRegex = regexp.MustCompile(pinModeNumericRegularExpression)
	singleCPURegex      = regexp.MustCompile(singleCPURegularExpression)
	firstCPURegex       = regexp.MustCompile(firstCPURegularExpression)
	lastCPURegex        = regexp.MustCompile(lastCPURegularExpression)
)

// getProcessAttributes takes the process pid, parses file /proc/<pid>/status and returns the process name and the
// Cpus_allowed_list if the file exists. It returns an error if file /proc/<pid>/status does not exist.
func getProcessAttributes(pid uint32) ([]byte, []byte, error) {
	var procName []byte
	var procCPUsAllowedList []byte

	f, err := os.Open(getStatusFile(pid))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if bytes.Equal(line[:5], []byte{'N', 'a', 'm', 'e', ':'}) {
			procName = bytes.TrimSpace(line[5:])
		}
		if bytes.Equal(line[:18],
			[]byte{'C', 'p', 'u', 's', '_',
				'a', 'l', 'l', 'o', 'w', 'e', 'd', '_',
				'l', 'i', 's', 't', ':'}) {
			procCPUsAllowedList = bytes.TrimSpace(line[18:])
		}
		if procName != nil && procCPUsAllowedList != nil {
			return procName, procCPUsAllowedList, nil
		}
	}
	return nil, nil, fmt.Errorf("no file name found for pid %d", pid)
}

func getStatusFile(pid uint32) string {
	return path.Join(procDirectory, fmt.Sprintf("%d", pid), statusFile)
}

// pinProcess takes the process ID, the current Cpus_allowed_list of the process, as well as the user provided
// pinMode. The pinMode can be first (first CPU of current process' Cpus_allowed_list), last (last CPU of current
// process' Cpus_allowed_list) or an explicit new Cpus_allowed_list for the process. An error indicates a parsin issue,
// or that the CPU affinity could not be set for the process.
func pinProcess(pid uint32, currentProcCPUsAllowedList []byte, pinMode string) error {
	newProcCPUsAllowedList, needsApply, err := getPinSet(currentProcCPUsAllowedList, pinMode)
	if err != nil {
		return err
	}
	if !needsApply {
		return nil
	}

	var cpuMask unix.CPUSet
	cpus, err := cpuset.Parse(newProcCPUsAllowedList)
	if err != nil {
		return err
	}
	for _, cpu := range cpus.List() {
		cpuMask.Set(cpu)
	}
	log.Printf("Pinning pid %d with pin-mode %q and current cpus_allowed_list %s to CPU set %s (mask %v)",
		pid, pinMode, currentProcCPUsAllowedList, newProcCPUsAllowedList, cpuMask)
	return unix.SchedSetaffinity(int(pid), &cpuMask)
}

// getPinSet takes the currentProcCPUsAllowedList and the new pinMode. The pinMode can be first (first CPU of current
// process' Cpus_allowed_list), last (last CPU of current process' Cpus_allowed_list) or an explicit new
// Cpus_allowed_list for the process. An error indicates that an invalid pinMode was provides, or that
// currentProcCPUsAllowedList could not be parsed. The boolean return value indicates if the change must be applied (true),
// or if nothing changed and the change need not be applied (false).
func getPinSet(currentProcCPUsAllowedList []byte, pinMode string) (string, bool, error) {
	if pinModeNumericRegex.MatchString(pinMode) {
		return pinMode, true, nil
	}

	if singleCPURegex.Match(currentProcCPUsAllowedList) {
		return string(currentProcCPUsAllowedList), false, nil
	}

	if pinMode == "first" {
		sMatches := firstCPURegex.FindSubmatch(currentProcCPUsAllowedList)
		if len(sMatches) != 2 {
			return "", false, fmt.Errorf("pinMode 'first' could not find a valid match in currentProcCPUsAllowedList %q",
				currentProcCPUsAllowedList)
		}
		return string(sMatches[1]), true, nil
	}
	if pinMode == "last" {
		sMatches := lastCPURegex.FindSubmatch(currentProcCPUsAllowedList)
		if len(sMatches) != 2 {
			return "", false, fmt.Errorf("pinMode 'first' could not find a valid match in currentProcCPUsAllowedList %q",
				currentProcCPUsAllowedList)
		}
		return string(sMatches[1]), true, nil
	}
	return "", false, fmt.Errorf("getPinSet was provided with invalid pinMode: %q", pinMode) // Should never happen.
}

// executeForPID runs the logic for a single process ID. Moved into separate function so that we can run it for
// netlink triggered and ticker triggered events.
func executeForPID(pid uint32, re *regexp.Regexp, discoveryMode *bool, pinMode *string) {
	// log.Printf("debug: Looking at process with pid %d", pid)
	// Get process attributes. If we can't, skip (directory for this process might be missing [process killed?]).
	procName, procCPUsAllowedList, err := getProcessAttributes(pid)
	if err != nil {
		// log.Printf("debug: Skipped, could not get attributes of process with pid %d ", pid)
		return
	}
	// If the process name does not match the user provided filter, skip.
	if !re.Match(procName) {
		// log.Printf("debug: Skipped, process with pid %d (%q) did not match regex %q", pid, procName, *procNameFilter)
		return
	}
	// If this is discovery mode, only print the process attributes, but do not pin.
	if *discoveryMode {
		log.Printf("PID: %d, Name: %s, cpus_allowed_list: %s\n", pid, procName, procCPUsAllowedList)
		return
	}
	// If this is not discovery mode, pin the process.
	if err := pinProcess(pid, procCPUsAllowedList, *pinMode); err != nil {
		log.Printf("Warning: Could not pin process; PID: %d, Name: %s, PinMode: %s, err: %q\n",
			pid, procName, *pinMode, err)
	}
}

// tickMode runs an (optional) ticker every tickSeconds.
func tickMode(ctx context.Context, re *regexp.Regexp, discoveryMode *bool, pinMode *string, tickSeconds *int) {
	ticker := time.NewTicker(time.Second * time.Duration(*tickSeconds))
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Printf("Tick - looking for processes at regular interval (every %d seconds)", *tickSeconds)
			entries, err := os.ReadDir(procDirectory)
			if err != nil {
				log.Fatalf("Could not read from proc directory %q, err: %q", procDirectory, err)
			}
			var pid int
			for _, entry := range entries {
				if entry.IsDir() {
					if pid, err = strconv.Atoi(entry.Name()); err == nil {
						executeForPID(uint32(pid), re, discoveryMode, pinMode)
					}
				}
			}
		case <-ctx.Done():
			log.Print("Ticker stopped")
			return
		}
	}
}

func main() {
	// Parse provided parameters.
	flag.Parse()
	if !*discoveryMode {
		if *procNameFilter == "" {
			log.Fatal("Must provide a proc-name-filter when discovery mode is off")
		}

		if !pinModeRegex.MatchString(*pinMode) {
			log.Fatal("Must provide a valid pin-mode when discovery mode is off")
		}
	} else {
		if *pinMode != "" {
			log.Fatal("Cannot provide a pin-mode in discovery-mode")
		}
	}

	// Can be empty or a valid regexp to find processes by name.
	re := regexp.MustCompile(*procNameFilter)

	// Check if /host/proc exists, in that case we'll be looking there for process information (important for containerization).
	if _, err := os.Stat("/host/proc"); err == nil {
		procDirectory = path.Join("/host", procDirectory)
	}

	log.Printf("Started with parameters: discovery-mode: %t, pin-mode: %q, proc-name-filter: %q, status-file: %s/%%d/%s",
		*discoveryMode, *pinMode, *procNameFilter, procDirectory, statusFile)

	ctx := context.TODO()
	// Add a ticker to regularly scan all processes. The ProcEventMonitor does not work for vhost processes,
	// unfortunately. It also can't hurt to have some extra logic that will (re)apply the settings every x seconds.
	if *tickSeconds > 0 {
		go tickMode(ctx, re, discoveryMode, pinMode, tickSeconds)
	}

	// netlink.ProcEventMonitor uses netlink to retrieve updates about processes. Must be run with sufficient privileges.
	procChan := make(chan netlink.ProcEvent)
	errorChan := make(chan error)
	if err := netlink.ProcEventMonitor(procChan, context.TODO().Done(), errorChan); err != nil {
		log.Fatalf("Got an error from netlink.ProcEventMonitor during initialization, err: %q", err)
	}
	for {
		select {
		case p := <-procChan:
			pid := p.Msg.Pid()
			executeForPID(pid, re, discoveryMode, pinMode)
		case err := <-errorChan:
			log.Fatalf("Got an error from netlink.ProcEventMonitor during select, err: %q", err)
		}
	}
}
