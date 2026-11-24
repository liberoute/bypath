package build

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestReleaseAssetContract pins the contract between the installer, the release
// workflow and the published assets. The installer downloads
// bypath-<variant>-linux-<arch> and verifies it against SHA256SUMS; the workflow
// must build exactly those names and stage SHA256SUMS next to them.
func TestReleaseAssetContract(t *testing.T) {
	root := filepath.Join("..", "..")
	installer := readContractFile(t, root, "install.sh")
	workflowText := readContractFile(t, root, filepath.Join(".github", "workflows", "build.yml"))

	var wf map[string]any
	if err := yaml.Unmarshal([]byte(workflowText), &wf); err != nil {
		t.Fatalf("workflow is not valid YAML: %v", err)
	}
	jobs := mapOf(t, wf["jobs"], "jobs")
	buildJob := mapOf(t, jobs["build"], "jobs.build")
	include := listOf(t, mapOf(t, mapOf(t, buildJob["strategy"], "strategy")["matrix"], "matrix")["include"], "matrix.include")

	// Published linux names, derived from the matrix exactly as the workflow
	// names its artifacts: env.BINARY_NAME-variant-os-arch.
	env := mapOf(t, wf["env"], "env")
	binaryName := fmt.Sprint(env["BINARY_NAME"])
	if !strings.Contains(workflowText, "${{ env.BINARY_NAME }}-${{ matrix.variant }}-${{ matrix.os }}-${{ matrix.arch }}") {
		t.Fatalf("workflow no longer names artifacts from env.BINARY_NAME, variant, os and arch")
	}
	published := map[string]bool{}
	for _, raw := range include {
		e := mapOf(t, raw, "matrix entry")
		if fmt.Sprint(e["os"]) != "linux" {
			continue
		}
		published[fmt.Sprintf("%s-%s-linux-%s", binaryName, e["variant"], e["arch"])] = true
	}

	// Installer default and variant handling.
	if !regexp.MustCompile(`(?m)^VARIANT="full"$`).MatchString(installer) {
		t.Fatalf(`install.sh must default to VARIANT="full"`)
	}
	m := regexp.MustCompile(`(?m)^FULL_ARCHES="([^"]*)"`).FindStringSubmatch(installer)
	if m == nil {
		t.Fatalf("install.sh does not declare FULL_ARCHES")
	}
	fullArches := strings.Fields(m[1])
	liteOnly := []string{}
	if lm := regexp.MustCompile(`(?m)^LITE_ONLY_ARCHES="([^"]*)"`).FindStringSubmatch(installer); lm != nil {
		liteOnly = strings.Fields(lm[1])
	}
	if !strings.Contains(installer, `ASSET="bypath-${VARIANT}-linux-${ARCH}"`) {
		t.Fatalf("install.sh asset name is no longer bypath-${VARIANT}-linux-${ARCH}")
	}
	if !strings.Contains(installer, `"${base}/SHA256SUMS"`) {
		t.Fatalf("install.sh does not verify against SHA256SUMS")
	}

	// Every architecture the installer can select must be published for the
	// variants it allows.
	if len(fullArches) == 0 {
		t.Fatalf("FULL_ARCHES is empty")
	}
	for _, arch := range fullArches {
		for _, variant := range []string{"full", "lite"} {
			name := fmt.Sprintf("%s-%s-linux-%s", binaryName, variant, arch)
			if !published[name] {
				t.Errorf("installer can request %s but the workflow matrix does not build it", name)
			}
		}
	}
	for _, arch := range liteOnly {
		if !published[fmt.Sprintf("%s-lite-linux-%s", binaryName, arch)] {
			t.Errorf("lite-only architecture %s has no lite build in the matrix", arch)
		}
	}

	// Reconciliation: every architecture the matrix publishes must be classified
	// as installer-supported, lite-only or manual-only, and the classes must not
	// name an architecture the matrix does not build.
	manual := []string{}
	if mm := regexp.MustCompile(`(?m)^MANUAL_ONLY_ARCHES="([^"]*)"`).FindStringSubmatch(installer); mm != nil {
		manual = strings.Fields(mm[1])
	}
	classified := map[string]bool{}
	for _, a := range append(append(append([]string{}, fullArches...), liteOnly...), manual...) {
		classified[a] = true
	}
	matrixArches := map[string]bool{}
	for _, raw := range include {
		e := mapOf(t, raw, "matrix entry")
		if fmt.Sprint(e["os"]) == "linux" {
			matrixArches[fmt.Sprint(e["arch"])] = true
		}
	}
	for a := range matrixArches {
		if !classified[a] {
			t.Errorf("linux/%s is built by the matrix but not classified in install.sh", a)
		}
	}
	for a := range classified {
		if !matrixArches[a] {
			t.Errorf("install.sh classifies %s but the matrix does not build it", a)
		}
	}

	// The binary count stated in the release notes must equal the matrix size.
	notes := readContractFile(t, root, "RELEASE_NOTES.md")
	cm := regexp.MustCompile(`publishes (\d+) binaries`).FindStringSubmatch(notes)
	if cm == nil {
		t.Errorf("RELEASE_NOTES.md does not state the binary count")
	} else if cm[1] != fmt.Sprint(len(include)) {
		t.Errorf("RELEASE_NOTES.md states %s binaries; the matrix builds %d", cm[1], len(include))
	}
	if strings.Contains(notes, "bypath-linux-") {
		t.Errorf("RELEASE_NOTES.md still lists the retired bypath-linux-<arch> names")
	}

	// The installer must not refer to the retired asset scheme.
	if strings.Contains(installer, "bypath-linux-") {
		t.Errorf("install.sh still refers to the retired bypath-linux-<arch> asset name")
	}

	// The workflow stages SHA256SUMS, not the retired checksums.txt name.
	if strings.Contains(workflowText, "checksums.txt") {
		t.Errorf("workflow still produces checksums.txt; the installer verifies SHA256SUMS")
	}
	if !strings.Contains(workflowText, "sha256sum bypath-* > SHA256SUMS") {
		t.Errorf("release-assets must write SHA256SUMS over the matrix binaries")
	}

	// Reproducible builds: BuildDate comes from the commit time, not the clock.
	if !strings.Contains(workflowText, "git log -1 --format=%ct") {
		t.Errorf("workflow BuildDate must derive from the commit time")
	}
	if strings.Contains(workflowText, "BuildDate=$(date") {
		t.Errorf("workflow BuildDate still reads the wall clock")
	}
	if !strings.Contains(readContractFile(t, root, "Makefile"), "git log -1 --date=format-local") {
		t.Errorf("Makefile BuildDate must derive from the commit time")
	}

	// Triggers: release branches validate; publication stays manual.
	on := mapOf(t, firstPresent(wf, "on", true), "on")
	push := mapOf(t, on["push"], "on.push")
	if !containsString(push["branches"], "release/**") {
		t.Errorf("release/** must trigger validation CI")
	}
	releaseAssets := mapOf(t, jobs["release-assets"], "jobs.release-assets")
	cond := fmt.Sprint(releaseAssets["if"])
	if !strings.Contains(cond, "refs/tags/v") || !strings.Contains(cond, "refs/heads/release/") {
		t.Errorf("release-assets must run for version tags and release branches, got %q", cond)
	}
	for _, step := range listOf(t, releaseAssets["steps"], "release-assets.steps") {
		text := fmt.Sprint(mapOf(t, step, "step"))
		if strings.Contains(text, "action-gh-release") || strings.Contains(text, "gh release create") {
			t.Errorf("release-assets must not publish a release")
		}
	}
	releaseJob := mapOf(t, jobs["release"], "jobs.release")
	if !strings.Contains(fmt.Sprint(releaseJob["if"]), "refs/heads/main") {
		t.Errorf("the dev release job must stay limited to main")
	}
}

func readContractFile(t *testing.T, root, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func mapOf(t *testing.T, v any, what string) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s is not a mapping (%T)", what, v)
	}
	return m
}

func listOf(t *testing.T, v any, what string) []any {
	t.Helper()
	l, ok := v.([]any)
	if !ok {
		t.Fatalf("%s is not a list (%T)", what, v)
	}
	return l
}

func firstPresent(m map[string]any, keys ...any) any {
	for _, k := range keys {
		if v, ok := m[fmt.Sprint(k)]; ok {
			return v
		}
	}
	return nil
}

func containsString(v any, want string) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if fmt.Sprint(item) == want {
			return true
		}
	}
	return false
}
