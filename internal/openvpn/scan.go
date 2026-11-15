package openvpn

import (
	"bufio"
	"strings"
)

// Refs lists the external files a profile references. It never opens them, so a
// frontend can ask the user for missing CA/cert/key files before importing.
// References are validated with the same rules the resolver applies.
type Refs struct {
	// Files are ca/cert/key/tls-auth/tls-crypt paths, in profile order.
	Files []string
	// AuthFile is the auth-user-pass file reference, if any.
	AuthFile string
}

// ScanRefs reads a profile and reports its external file references without
// resolving them. Inline PEM blocks are not reported.
func ScanRefs(path string) (Refs, error) {
	data, err := readProfileFile(path)
	if err != nil {
		return Refs{}, err
	}
	return scanRefs(string(data))
}

func scanRefs(content string) (Refs, error) {
	var out Refs
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), maxProfileSize)

	inBlock := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if inBlock != "" {
			if strings.EqualFold(line, "</"+inBlock+">") {
				inBlock = ""
			}
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			inBlock = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.ToLower(fields[0])
		switch {
		case externalPEMDirectives[name]:
			ref := fields[1]
			if err := validateRelativeRef(ref); err != nil {
				return Refs{}, err
			}
			if !seen[ref] {
				seen[ref] = true
				out.Files = append(out.Files, ref)
			}
		case name == "auth-user-pass":
			ref := fields[1]
			if err := validateRelativeRef(ref); err != nil {
				return Refs{}, err
			}
			out.AuthFile = ref
		}
	}
	if err := scanner.Err(); err != nil {
		return Refs{}, err
	}
	return out, nil
}
