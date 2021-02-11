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

// ScanTask holds the data for an upcoming scan. The namp scans are created from these populated items
type ScanTask struct {
	Host             string
	Ports            string
	ScanTypeSwitches string
	Stage            int
}

var out io.Writer = os.Stdout

func main() {
	banner()
	fmt.Println("")

	writer := bufio.NewWriter(out)
	initialScans := make(chan ScanTask, 1)
	followUpScans := []ScanTask{}
	var wg sync.WaitGroup

	ch := readStdin()
	go func() {
		//translate stdin channel to initial scans channel
		for u := range ch {
			newScan := ScanTask{
				Host:             u,
				Ports:            "",
				ScanTypeSwitches: "",
				Stage:            1,
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

	// fire off the initial set of scans. This will likely just result in a set of 'nmap <host>' scans. We then adapt after this.
	for {
		for u := range initialScans {
			wg.Add(1)
			go func(scanTask ScanTask) {
				defer wg.Done()
				fmt.Println("Performing the scan of:", scanTask.Host)
				fmt.Println("[ Stage", scanTask.Stage, "] Host:", scanTask.Host, "Ports:", scanTask.Ports, "Args:", scanTask.ScanTypeSwitches)

				cmd := generateCommandFromSettings(scanTask)
				result := fireOffScan(cmd)
				needAnotherScan, scanTypeRef, targetPorts := parseResults(scanTask, result)

				if needAnotherScan {
					newTask, err := createNextTask(scanTask, scanTypeRef, targetPorts)
					if err != nil {
						return
					}

					followUpScans = append(followUpScans, newTask)
				}
			}(u)
		}

		wg.Wait()

		if len(followUpScans) > 0 {
			initialScans = make(chan ScanTask, 1)

			go func() {
				// refill the initialScans channel with the follow up scan tasks gathered previously
				for _, s := range followUpScans {
					initialScans <- s
				}
				close(initialScans)
				followUpScans = []ScanTask{}
			}()
		} else {
			break // quit the 'while' loop
		}
	}

	// just in case anything is still in buffer
	writer.Flush()
}

func banner() {
	fmt.Println("---------------------------------------------------")
	fmt.Println("Brrrrrmap -> skidlife")
	fmt.Println("")
	fmt.Println("---------------------------------------------------")
}

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

func generateCommandFromSettings(scanTask ScanTask) []string {
	args := []string{}

	// check the scan task port information and add the data as required
	if scanTask.Ports != "" {
		args = append(args, scanTask.Ports)
	} else {
		// we are doing the initial scan here as no ports are specified (top 1k by default, thanks nmap)
	}

	if scanTask.ScanTypeSwitches != "" {
		// specific scan data
	} else {
		// likely the initial scan, so we don't have any extra information to add here
	}

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

func parseResults(scanData ScanTask, results string) (bool, string, string) {
	// pn -> adds the -Pn as we want to skip look up
	// fr -> full range port look up as we got a successful initial scan
	// deeper -> deeper scan of the target ports that were identified from this result set
	// udp -> do a quick UDP look up

	// return a value (string) to specify the next type of scan we need

	fmt.Println(results)
	nextScanRef := ""
	targetPorts := ""

	// first things first, do we need to re-scan initially
	if strings.Contains(results, "Host seems down.") && strings.Contains(results, "try -Pn") {
		nextScanRef = "pn"
		targetPorts = "-p-"
	} else {
		// we probably have results here. Let's split and loop the lines looking for our target data
		splitLines := strings.Split(results, "\n")
		openPorts := []string{}

		if len(splitLines) > 0 {
			for _, l := range splitLines {
				if strings.Contains(l, "/tcp open") {
					openPorts = append(openPorts, strings.Split(l, "/tcp")[0])
				}
			}
		}

		// if our current scan args were NOT a deep scan or full range, then we can schedule another one
		if scanData.Ports != "-p-" && !strings.Contains(scanData.ScanTypeSwitches, "-TODO") {
			nextScanRef = "fr"
			targetPorts = "-p-"
		}
	}

	return nextScanRef != "", nextScanRef, targetPorts
}

func createNextTask(previousTask ScanTask, scanType string, ports string) (ScanTask, error) {
	args := ""

	// TODO: allow multiple scanTypes to be specified: i.e pn|fr|deeper
	switch scanType {
	case "pn":
		args = "-Pn"
		break

	case "fr":
		args = "-sT"
		ports = "-p-"
		break

	case "deeper":
		break

	case "udp":
		args = "-sU"
		ports = "--top-ports 100"
		break
	}

	newScan := ScanTask{
		Host:             previousTask.Host,
		Ports:            ports,
		ScanTypeSwitches: args,
		Stage:            previousTask.Stage + 1,
	}

	return newScan, nil
}
