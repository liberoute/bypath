package main

import (
	"fmt"
	"github.com/liberoute/bypath/internal/serviceop"
	"os"
)

func cmdServiceWorker(args []string) {
	var err error
	if len(args) == 1 && args[0] == "verify" {
		err = serviceop.VerifyWorker()
	} else if len(args) == 0 {
		err = serviceop.WorkerAllowed()
		if err == nil {
			err = serviceop.New().Run()
		}
	} else {
		err = serviceop.ErrUnsupported
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "service worker failed")
		os.Exit(1)
	}
}
