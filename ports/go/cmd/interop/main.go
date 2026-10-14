// Command interop is the Go agent for ports/conformance/interop.py:
//
//	interop URL FLEET_FILE AGENT_ID INSTANCE_ID
//
// with the token in SMARTSWITCH_AGENT_TOKEN. It polls every 100 ms and prints "STATUS <code>" whenever
// the status code changes, and exits when standard input closes or after 60 s.
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	ss "github.com/SmartTasksOrg/sf-smartswitch/ports/go/smartswitch"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: interop URL FLEET_FILE AGENT_ID INSTANCE_ID")
		os.Exit(2)
	}
	ag, err := ss.NewAgent(ss.AgentConfig{URL: os.Args[1], Token: os.Getenv("SMARTSWITCH_AGENT_TOKEN"), FleetFile: os.Args[2],
		AgentID: os.Args[3], InstanceID: os.Args[4], PollInterval: 100 * time.Millisecond, Timeout: time.Second})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(done)
	}()
	end := time.After(60 * time.Second)
	last := ""
	for {
		s := ag.PollOnce()
		if s.Code != last {
			last = s.Code
			fmt.Fprintln(os.Stdout, "STATUS "+s.Code) // os.Stdout is unbuffered
		}
		select {
		case <-done:
			return
		case <-end:
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
