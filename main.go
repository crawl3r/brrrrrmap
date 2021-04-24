package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Scanner struct {
	ID               int
	Host             string
	CurrentTask      *ScanTask
	NextTask         *ScanTask
	CompletedTasks   []*ScanTask
	FilenameFriendly string
	OutputDir        string
}

type ScanTask struct {
	Host             string
	Ports            string
	ScanTypeSwitches string
	Stage            int
	ScanTypeRef      string
	RawOutputName    string
	IsComplete       bool
}

var out io.Writer = os.Stdout

func main() {
	writer := bufio.NewWriter(out)
	initialScans := make(chan ScanTask, 1)
	ch := readStdin()
	go func() {
		//translate stdin channel to initial scans channel
		for u := range ch {
			newScan := ScanTask{
				Host:             u,
				Ports:            "",
				ScanTypeSwitches: "-sn", // initial ping of the host
				Stage:            1,
				ScanTypeRef:      "sweep",
				RawOutputName:    "_sweep_raw.txt",
				IsComplete:       false,
			}
			initialScans <- newScan
		}
		close(initialScans)
	}()

	// flush to writer periodically
	t := time.NewTicker(time.Millisecond * 500)
	defer t.Stop()
	go func() {
		for {
			select {
			case <-t.C:
				writer.Flush()
			}
		}
	}()

	var wg sync.WaitGroup
	scanners := []*Scanner{}

	for s := range initialScans {
		newScanner := &Scanner{}
		newScanner.Start(s, 1)

		wg.Add(1)
		go func(newScanner *Scanner) {
			defer wg.Done()

			newScanner.Run()
		}(newScanner)

		scanners = append(scanners, newScanner)
	}

	wg.Wait()

	writer.Flush()
}

func (s *Scanner) Start(initialTask ScanTask, i int) {
	s.ID = i
	s.Host = initialTask.Host
	s.NextTask = &initialTask

	filenameFriendly := strings.Replace(initialTask.Host, ".", "_", -1)
	s.FilenameFriendly = filenameFriendly
	s.OutputDir = filenameFriendly

	err := os.Mkdir(s.OutputDir, 0755)
	if err != nil {
		log.Fatalln(err)
	}

	s.NextTask.RawOutputName = s.OutputDir + "/" + filenameFriendly + s.NextTask.RawOutputName
}

func (s *Scanner) Run() {
	// fire off our first task
	fmt.Printf("[***] Starting first scan for: %s\n", s.Host)
	s.DoNextTask()

	// run forever, until we do NOT have a next task anyway
	for {
		if s.CurrentTask.IsComplete == true && s.NextTask != nil {
			s.DoNextTask()
		} else {
			break
		}
	}
}

func (s *Scanner) CreateNewTask(previousTask *ScanTask, scanType string, ports string) {
	args := ""

	// TODO: allow multiple scanTypes to be specified: i.e pn|fr|deeper
	switch scanType {
	case "quick_nodiscovery":
		args = "-Pn"
		ports = ""
		break

	case "fullrange":
		args = "-sT"
		ports = "-p-"
		break

	case "deeper":
		args = "-sT" // todo: proper switches for deeper analysis
		break

	case "udp":
		args = "-sU"
		ports = "--top-ports 100"
		break
	}

	newScan := &ScanTask{
		Host:             previousTask.Host,
		Ports:            ports,
		ScanTypeSwitches: args,
		Stage:            previousTask.Stage + 1,
		ScanTypeRef:      scanType,
		RawOutputName:    s.OutputDir + "/" + s.FilenameFriendly + "_" + scanType + "_raw.txt",
		IsComplete:       false,
	}

	s.NextTask = newScan
}

func (s *Scanner) DoNextTask() {
	s.CurrentTask = s.NextTask
	s.NextTask = nil

	cmd := generateCommandFromSettings(s.CurrentTask)
	result := fireOffScan(cmd)
	needAnotherScan, scanTypeRef, targetPorts := parseResults(s.CurrentTask, result)

	s.CompletedTasks = append(s.CompletedTasks, s.CurrentTask)
	s.CurrentTask.IsComplete = true

	if needAnotherScan {
		s.CreateNewTask(s.CurrentTask, scanTypeRef, targetPorts)
	}
}

//
func generateCommandFromSettings(scanTask *ScanTask) []string {
	args := []string{}

	// check the scan task port information and add the data as required
	if scanTask.Ports != "" {
		args = append(args, scanTask.Ports)
	} else {
		// we are doing the initial scan here as no ports are specified (top 1k by default, thanks nmap)
	}

	if scanTask.ScanTypeSwitches != "" {
		// specific scan data
		// TODO
	} else {
		// likely the initial scan, so we don't have any extra information to add here
	}

	args = append(args, "-oN")
	args = append(args, scanTask.RawOutputName)

	// the last thing we do is chuck on the target host providing it has been filled in correctly
	if scanTask.Host != "" {
		args = append(args, scanTask.Host)
	}

	return args
}

func fireOffScan(args []string) string {
	// fire off nmap scan with the passed in args
	out, err := exec.Command("nmap", args...).Output()

	if err != nil {
		log.Fatal(err)
	}

	return string(out)
}

func parseResults(scanData *ScanTask, results string) (bool, string, string) {
	// pingsweep -> just a ping sweep with -sn to check if hosts are up
	// quick_nodiscovery -> common ports with -Pn
	// fullrange -> full range port look up as we got a successful initial scan
	// deeper -> deeper scan of the target ports that were identified from this result set
	// udp -> do a quick UDP look up

	// return a value (string) to specify the next type of scan we need

	fmt.Println(results)
	nextScanRef := ""
	targetPorts := ""

	if scanData.ScanTypeRef == "sweep" {
		if strings.Contains(results, "Host is up (") {
			// host is up, schedule a full range scan on TCP
			nextScanRef = "fullrange"
			targetPorts = "-p-"
		} else {
			// is host down? Let's force a quick -Pn scan anyway to check common ports
			nextScanRef = "quick_nodiscovery"
			targetPorts = ""
		}
	} else if scanData.ScanTypeRef == "quick_nodiscovery" {
		// this was our 2nd attempt at seeing if the host was up, if they have ICMP disabled
		if strings.Contains(results, "Host is up (") {
			// host is up, schedule a full range scan on TCP
			nextScanRef = "fullrange"
			targetPorts = "-p-"
		}
		// host is down if we didn't go in the above
	} else {
		// First let's try find some loot for this specific scan:
		// findReportableLootInResults(scanData.Host, results)

		// if our current scan args were NOT a deep scan or full range, then let's schedule another one with full port range
		if strings.Contains(scanData.ScanTypeRef, "deeper") {
			// should end it??
		} else {
			// Now we react based on the current scan results (loot aside) and generate our next scan for the host (if one is required)
			splitLines := strings.Split(results, "\n")
			openPorts := []string{}

			// let's try and get a list of open ports to make sure we focus fire on the open ones with deeper analysis
			if len(splitLines) > 0 {
				for _, l := range splitLines {
					if strings.Contains(l, "/tcp") && strings.Contains(l, "open") {
						openPorts = append(openPorts, strings.Split(l, "/tcp")[0])
					}
				}
			}

			if len(openPorts) > 0 {
				// we have found at least 1 open port on the host. Let's schedule a deeper scan
				fmt.Println("[*] Scheduling deeper port analysis scans for host:", scanData.Host)
				identifiedPorts := ""
				for _, p := range openPorts {
					identifiedPorts += p + ","
				}
				// remove the last , because coding is hard
				identifiedPorts = identifiedPorts[:len(identifiedPorts)-1]

				nextScanRef = "deeper"
				targetPorts = "-p" + identifiedPorts
			}
		}
	}

	return nextScanRef != "", nextScanRef, targetPorts
}

// ---- input from stdin
func readStdin() <-chan string {
	lines := make(chan string)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			url := strings.ToLower(sc.Text())
			if url != "" {
				lines <- url
			}
		}
	}()
	return lines
}
