// Command verify-tun2socks validates a staged tun2socks binary before it is
// embedded into a Bypath Full-embed build.
//
// It is a build-time gate: the Makefile runs it between staging and `go build`,
// so an asset for the wrong architecture, a different release, or a different
// upstream commit fails the build instead of shipping.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/liberoute/bypath/internal/embedbin"
)

func main() {
	asset := flag.String("asset", "", "path to the staged binary (default: every staged asset that exists)")
	goos := flag.String("goos", "", "target GOOS (with -asset)")
	goarch := flag.String("goarch", "", "target GOARCH (with -asset)")
	goarm := flag.String("goarm", "", "target GOARM (only applies to arm)")
	flag.Parse()

	if *asset != "" {
		a, ok := embedbin.AssetFor(*goos, *goarch, *goarm)
		if !ok {
			fmt.Fprintf(os.Stderr, "verify-tun2socks: no pinned asset for %s/%s/%s\n", *goos, *goarch, *goarm)
			os.Exit(1)
		}
		if err := embedbin.VerifyAsset(*asset, a); err != nil {
			fmt.Fprintf(os.Stderr, "verify-tun2socks: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(record(*asset, a))
		return
	}

	failed := false
	for _, a := range embedbin.StagedTun2socks {
		path := filepath.Join("internal", "embedbin", "assets", a.File)
		if _, err := os.Stat(path); err != nil {
			fmt.Printf("SKIP %s (not staged)\n", path)
			continue
		}
		if err := embedbin.VerifyAsset(path, a); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", path, err)
			failed = true
			continue
		}
		fmt.Println(record(path, a))
	}
	if failed {
		os.Exit(1)
	}
}

func record(path string, a embedbin.Asset) string {
	return fmt.Sprintf("OK %s goos=%s goarch=%s goarm=%s size=%d sha256=%s version=%s commit=%s",
		path, a.GOOS, a.GOARCH, a.GOARM, a.Size, a.SHA256, a.Version, a.Commit)
}
