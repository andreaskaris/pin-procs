package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/utils/cpuset"
)

const (
	statusFile                      = "/proc/%d/status"
	pinModeNumericRegularExpression = `^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$`
	pinModeRegularExpression        = `^first$|^last$|` + pinModeNumericRegularExpression
	firstCPURegularExpression       = `^([0-9]+)[^0-9]`
	lastCPURegularExpression        = `[^0-9]([0-9]+)$*`
)

var (
	procNameFilter      = flag.String("proc-name-filter", "", "filter for process names to be pinned")
	pinMode             = flag.String("pin-mode", "", "instruction for vCPU to pin to (accepted values: 'first', 'last', [0-9]+,)")
	discoveryMode       = flag.Bool("discovery-mode", false, "discovery mode will print all discovered processes that match proc-name-filter")
	pinModeRegex        = regexp.MustCompile(pinModeRegularExpression)
	pinModeNumericRegex = regexp.MustCompile(pinModeNumericRegularExpression)
	firstCPURegex       = regexp.MustCompile(firstCPURegularExpression)
	lastCPURegex        = regexp.MustCompile(lastCPURegularExpression)
)

// getProcessAttributes takes the process pid, parses file /proc/<pid>/status and returns the process name and the
// Cpus_allowed_list if the file exists. It returns an error if file /proc/<pid>/status does not exist.
func getProcessAttributes(pid uint32) ([]byte, []byte, error) {
	var procName []byte
	var procCPUsAllowedList []byte

	f, err := os.Open(fmt.Sprintf(statusFile, pid))
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

// pinProcess takes the process ID, the current Cpus_allowed_list of the process, as well as the user provided
// pinMode. The pinMode can be first (first CPU of current process' Cpus_allowed_list), last (last CPU of current
// process' Cpus_allowed_list) or an explicit new Cpus_allowed_list for the process. An error indicates a parsin issue,
// or that the CPU affinity could not be set for the process.
func pinProcess(pid uint32, currentProcCPUsAllowedList []byte, pinMode string) error {
	newProcCPUsAllowedList, err := getPinSet(currentProcCPUsAllowedList, pinMode)
	if err != nil {
		return err
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
// currentProcCPUsAllowedList could not be parsed.
func getPinSet(currentProcCPUsAllowedList []byte, pinMode string) (string, error) {
	if pinModeNumericRegex.MatchString(pinMode) {
		return pinMode, nil
	}
	if pinMode == "first" {
		sMatches := firstCPURegex.FindSubmatch(currentProcCPUsAllowedList)
		if len(sMatches) != 2 {
			return "", fmt.Errorf("pinMode 'first' could not find a valid match in currentProcCPUsAllowedList %q",
				currentProcCPUsAllowedList)
		}
		return string(sMatches[1]), nil
	}
	if pinMode == "last" {
		sMatches := lastCPURegex.FindSubmatch(currentProcCPUsAllowedList)
		if len(sMatches) != 2 {
			return "", fmt.Errorf("pinMode 'first' could not find a valid match in currentProcCPUsAllowedList %q",
				currentProcCPUsAllowedList)
		}
		return string(sMatches[1]), nil
	}
	return "", fmt.Errorf("getPinSet was provided with invalid pinMode: %q", pinMode) // Should never happen.
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

			// Get process attributes. If we can't, skip (directory for this process might be missing [process killed?]).
			procName, procCPUsAllowedList, err := getProcessAttributes(pid)
			if err != nil {
				continue
			}
			// If the process name does not match the user provided filter, skip.
			if !re.Match(procName) {
				continue
			}
			// If this is discovery mode, only print the process attributes, but to not pin.
			if *discoveryMode {
				log.Printf("PID: %d, Name: %s, cpus_allowed_list: %s\n", pid, procName, procCPUsAllowedList)
				continue
			}
			// If this is not discovery mode, pin the process.
			if err := pinProcess(pid, procCPUsAllowedList, *pinMode); err != nil {
				log.Printf("Warning: Could not pin process; PID: %d, Name: %s, PinMode: %s, err: %q\n",
					pid, procName, *pinMode, err)
			}
		case err := <-errorChan:
			log.Fatalf("Got an error from netlink.ProcEventMonitor during select, err: %q", err)
		}
	}
}
