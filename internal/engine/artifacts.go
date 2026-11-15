package engine

import (
	"fmt"
	"sort"
	"strings"
)

// Artifact describes one pinned engine release asset. SHA256 is the digest
// published by the upstream project for exactly this file. Downloads are only
// accepted when they match it byte for byte.
type Artifact struct {
	URL string
	// Name is the release asset file name.
	Name string
	// Binary is the executable's name inside the archive when it differs from
	// the engine name (tun2socks release zips carry the platform suffix).
	Binary string
	SHA256 string
}

type artifactKey struct{ engine, goos, goarch string }

const (
	singBoxVersion   = "1.14.4"
	xrayVersion      = "26.10.31"
	tun2socksVersion = "2.5.2"
	tun2socksBaseURL = "https://github.com/xjasonlyu/tun2socks/releases/download/v" + tun2socksVersion
)

var pinnedArtifacts = map[artifactKey]Artifact{
	{"sing-box", "linux", "amd64"}:   singBoxArtifact("linux-amd64.tar.gz", "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"),
	{"sing-box", "linux", "arm64"}:   singBoxArtifact("linux-arm64.tar.gz", "436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26"),
	{"sing-box", "linux", "arm"}:     singBoxArtifact("linux-armv7.tar.gz", "fd164ed45ebc784f657a3e1d0e0ad0f68afdcff864ee57122c2cfed3ddb80a00"),
	{"sing-box", "linux", "386"}:     singBoxArtifact("linux-386.tar.gz", "efb46daaa48ee55e090bd1dfcaee34bfbe9bdbd9b89fa9f328d25f81a619e865"),
	{"sing-box", "linux", "mipsle"}:  singBoxArtifact("linux-mipsle.tar.gz", "858ff0251122d424269257a5e24047d71776b3dae9e05e15f710727b2f91042b"),
	{"sing-box", "windows", "amd64"}: singBoxArtifact("windows-amd64.zip", "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df"),

	{"xray", "linux", "amd64"}:   xrayArtifact("linux", "64", "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214"),
	{"xray", "linux", "arm64"}:   xrayArtifact("linux", "arm64-v8a", "1811c8f1da0c3b6dc707ebaf1c8390e987ba39859a8f0a7aadd8526157f2ec8d"),
	{"xray", "linux", "arm"}:     xrayArtifact("linux", "arm32-v7a", "2387f55239ee7799fd67d5382e79f589c1da07a97d993e86b058f2290b8e456b"),
	{"xray", "windows", "amd64"}: xrayArtifact("windows", "64", "2e04a9995a6f2ad1b28c0bb25c708ecb2695e43a1c9c7889c4b6ac2b48cf7a6a"),
	{"xray", "windows", "arm64"}: xrayArtifact("windows", "arm64-v8a", "db062e8a177facacc8ae53d4c9c0df4132b13fc3a89acda6f21d92d36633077e"),

	// tun2socks is the transparent-gateway data path for engines that provide
	// SOCKS only (xray, OpenVPN via sing-box). v2.5.2 is the pinned release;
	// the digests were computed from the official GitHub release assets and the
	// amd64 binary reports commit 2b494a7, the commit the v2.5.2 tag points to.
	{"tun2socks", "linux", "amd64"}: tun2socksArtifact("amd64", "4aa7737009a9f06b9f4957c4fc12932ae0cd2039471d2ae4e5d4666ffeb40a2e"),
	{"tun2socks", "linux", "arm64"}: tun2socksArtifact("arm64", "b83bc4961b33aa3ec0399c801a97c2c47766462991ffa488a4cbaee1ab3e0bff"),
	{"tun2socks", "linux", "arm"}:   tun2socksArtifact("armv7", "089dd9652baa70862d00f465c81a5df3ab7129e82dca73edea36d0cfd8152b89"),
}

func singBoxArtifact(suffix, sha string) Artifact {
	name := fmt.Sprintf("sing-box-%s-%s", singBoxVersion, suffix)
	return Artifact{
		URL:    fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/%s", singBoxVersion, name),
		Name:   name,
		SHA256: sha,
	}
}

func xrayArtifact(osName, arch, sha string) Artifact {
	name := fmt.Sprintf("Xray-%s-%s.zip", osName, arch)
	return Artifact{
		URL:    fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/v%s/%s", xrayVersion, name),
		Name:   name,
		SHA256: sha,
	}
}

func tun2socksArtifact(arch, sha string) Artifact {
	binary := fmt.Sprintf("tun2socks-linux-%s", arch)
	return Artifact{
		URL:    fmt.Sprintf("%s/%s.zip", tun2socksBaseURL, binary),
		Name:   binary + ".zip",
		Binary: binary,
		SHA256: sha,
	}
}

// artifactFor returns the verified release asset for the requested platform.
// An unpinned platform is an error: downloading an unverified or wrong-arch
// binary is never an acceptable fallback.
func ArtifactFor(name, goos, goarch string) (Artifact, error) {
	if a, ok := pinnedArtifacts[artifactKey{name, goos, goarch}]; ok {
		return a, nil
	}
	return Artifact{}, fmt.Errorf("no verified %s build for %s/%s; supported: %s",
		name, goos, goarch, strings.Join(supportedPlatforms(name), ", "))
}

func supportedPlatforms(name string) []string {
	var out []string
	for k := range pinnedArtifacts {
		if k.engine == name {
			out = append(out, k.goos+"/"+k.goarch)
		}
	}
	sort.Strings(out)
	return out
}
