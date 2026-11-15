package geo

import (
	"bufio"
	"fmt"
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
	matched, _ := walkXrayCategories(path, fn)
	return matched
}

// ValidateXrayDatFile reports whether path is a complete category list xray can
// load: every entry parses, the list is non-empty, and the file is large enough
// that xray's asset lookup will consider it. Entries are checked the way xray's
// loader checks them — locate by code, then proto.Unmarshal the entry — so a
// file whose outer framing is intact but whose domain or CIDR messages are
// malformed is rejected here instead of aborting xray at startup.
func ValidateXrayDatFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() < 1000 {
		return fmt.Errorf("implausibly small (%d bytes)", info.Size())
	}
	count := 0
	_, err = walkXrayCategories(path, func(string) bool {
		count++
		return false
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("no categories")
	}
	return nil
}

func walkXrayCategories(path string, fn func(code string) bool) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 64*1024)
	for {
		tag, err := br.ReadByte()
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if tag != 0x0a { // top level: repeated field 1 (entry message)
			return false, fmt.Errorf("unexpected protobuf tag 0x%02x", tag)
		}
		bodyLen, err := readVarint(br)
		if err != nil {
			return false, err
		}
		if bodyLen < 2 || bodyLen > 1<<28 {
			return false, fmt.Errorf("implausible entry length %d", bodyLen)
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return false, err
		}
		code, ok := entryCode(body)
		if !ok {
			return false, fmt.Errorf("entry has no category code")
		}
		if err := validateEntryBody(body); err != nil {
			return false, fmt.Errorf("category %q: %w", code, err)
		}
		if fn(code) {
			return true, nil
		}
	}
}

// validateEntryBody mirrors what xray does after locating a code: the whole
// entry is handed to proto.Unmarshal. Both lists carry field 1 (the code string)
// and field 2 (repeated Domain or CIDR); only field 2 is a nested message the
// parser opens, so only that field is walked recursively. Every other field must
// merely be valid wire data, which is exactly when proto.Unmarshal succeeds.
func validateEntryBody(body []byte) error {
	return walkProtoFields(body, func(num, wire int, payload []byte) error {
		if num != 2 || wire != 2 {
			return nil
		}
		return walkProtoFields(payload, func(int, int, []byte) error { return nil })
	})
}

// walkProtoFields validates the wire format of one protobuf message body,
// handing each length-delimited payload to fn. A field number of zero, an
// unknown wire type, or a length that runs past the body is what proto.Unmarshal
// rejects, so the same checks reject here.
func walkProtoFields(body []byte, fn func(num, wire int, payload []byte) error) error {
	for off := 0; off < len(body); {
		tag, n := consumeVarintField(body[off:])
		if n <= 0 {
			return fmt.Errorf("truncated field tag at offset %d", off)
		}
		off += n
		num, wire := tag>>3, tag&7
		if num <= 0 {
			return fmt.Errorf("invalid field number at offset %d", off-n)
		}
		switch wire {
		case 0:
			_, n := consumeVarintField(body[off:])
			if n <= 0 {
				return fmt.Errorf("invalid varint in field %d", num)
			}
			off += n
		case 1:
			if off+8 > len(body) {
				return fmt.Errorf("truncated fixed64 in field %d", num)
			}
			off += 8
		case 2:
			length, n := consumeVarintField(body[off:])
			if n <= 0 || length < 0 || off+n+length > len(body) {
				return fmt.Errorf("invalid length in field %d", num)
			}
			off += n
			if err := fn(num, wire, body[off:off+length]); err != nil {
				return err
			}
			off += length
		case 5:
			if off+4 > len(body) {
				return fmt.Errorf("truncated fixed32 in field %d", num)
			}
			off += 4
		default:
			return fmt.Errorf("invalid wire type %d in field %d", wire, num)
		}
	}
	return nil
}

// consumeVarintField decodes a base-128 varint, returning the value and the
// number of bytes consumed (0 on malformed input).
func consumeVarintField(b []byte) (int, int) {
	var x uint64
	for i := 0; i < len(b) && i < 10; i++ {
		x |= uint64(b[i]&0x7f) << (7 * i)
		if b[i]&0x80 == 0 {
			if x > uint64(1<<62-1) {
				return 0, 0
			}
			return int(x), i + 1
		}
	}
	return 0, 0
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
// ("SRS"). This is only a cheap prefilter: the magic says nothing about the
// format version or whether the compressed payload decodes. Use ValidSRSFile for
// the decision that gates a rule.
func ValidateSRS(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x53 && b[1] == 0x52 && b[2] == 0x53
}
