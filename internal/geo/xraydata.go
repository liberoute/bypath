package geo

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// XrayAssetCandidates lists the places xray looks for a .dat asset, in priority
// order. dir is the directory bypath provisions (engines or geo); xray itself
// would only check its executable directory and the system paths.
func XrayAssetCandidates(dir, name string) []string {
	var out []string
	if dir != "" {
		out = append(out, filepath.Join(dir, name))
	}
	out = append(out,
		filepath.Join("/usr/local/share/xray", name),
		filepath.Join("/usr/share/xray", name),
		filepath.Join("/opt/share/xray", name),
	)
	return out
}

// FindXrayAsset returns the first existing candidate with non-trivial content,
// or "" when no usable asset is installed.
func FindXrayAsset(dir, name string) string {
	for _, p := range XrayAssetCandidates(dir, name) {
		if info, err := os.Stat(p); err == nil && info.Size() > 1000 {
			return p
		}
	}
	return ""
}

// FindXrayAssetDir returns the directory holding xray's geo databases, searching
// the given directories in order before xray's standard locations. The embedded
// engine points xray.location.asset at it.
func FindXrayAssetDir(dirs ...string) string {
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		for _, dir := range dirs {
			if p := FindXrayAsset(dir, name); p != "" {
				return filepath.Dir(p)
			}
		}
	}
	return ""
}

// HasXrayCategory reports whether a v2fly/xray .dat file contains the given
// category code. xray aborts startup when a rule references a code the file does
// not contain, so the generator must check before emitting geoip:/geosite: rules.
//
// The scanner mirrors xray's matcher loader: the document is a protobuf
// GeoIPList/GeoSiteList — repeated field 1, each entry a length-delimited
// message whose field 1 is the category code string.
func HasXrayCategory(path, code string) bool {
	if code == "" {
		return false
	}
	return ScanXrayCategories(path, func(c string) bool { return c == code })
}

// FindXrayCategory returns the spelling of code that the .dat file actually
// contains. v2fly's shared lists publish country lists as "CATEGORY-XX" while
// sing-box rule sets use a bare country code; a rule written as geosite:cc must match
// either spelling, and xray only accepts the exact tag present in the file.
func FindXrayCategory(path, code string) (string, bool) {
	if code == "" {
		return "", false
	}
	want := strings.ToLower(code)
	var found string
	ScanXrayCategories(path, func(c string) bool {
		lc := strings.ToLower(c)
		if lc == want || lc == "category-"+want {
			found = c
			return true
		}
		return false
	})
	return found, found != ""
}

// ListXrayCategories returns the category codes present in a .dat file, in file
// order. Malformed input stops the scan and returns what was read so far.
func ListXrayCategories(path string) []string {
	var out []string
	ScanXrayCategories(path, func(c string) bool {
		out = append(out, c)
		return false
	})
	return out
}

// ScanXrayCategories walks the category entries of a .dat file, calling fn with
// each code. It returns true when fn reports a match, and false when the file
// ends, cannot be read, or is not a category list.
func ScanXrayCategories(path string, fn func(code string) bool) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 64*1024)
	for {
		tag, err := br.ReadByte()
		if err != nil {
			return false
		}
		if tag != 0x0a { // top level: repeated field 1 (entry message)
			return false
		}
		bodyLen, err := readVarint(br)
		if err != nil || bodyLen < 2 || bodyLen > 1<<28 {
			return false
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return false
		}
		code, ok := entryCode(body)
		if !ok {
			return false
		}
		if fn(code) {
			return true
		}
	}
}

// entryCode extracts field 1 (the category code string) from one entry message.
func entryCode(body []byte) (string, bool) {
	if len(body) < 2 || body[0] != 0x0a {
		return "", false
	}
	n, off := 0, 1
	for shift := uint(0); shift < 64; shift += 7 {
		if off >= len(body) {
			return "", false
		}
		b := body[off]
		off++
		n |= int(b&0x7f) << shift
		if b&0x80 == 0 {
			if n <= 0 || off+n > len(body) {
				return "", false
			}
			return string(body[off : off+n]), true
		}
	}
	return "", false
}

func readVarint(r *bufio.Reader) (int, error) {
	var x uint64
	for shift := uint(0); shift < 64; shift += 7 {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		x |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return int(x), nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

// ValidateSRS reports whether b starts with the sing-box rule-set binary magic
// ("SRS"). A truncated HTML error page served with HTTP 200 must never be
// installed as a rule set: sing-box would refuse to start with it.
func ValidateSRS(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x53 && b[1] == 0x52 && b[2] == 0x53
}