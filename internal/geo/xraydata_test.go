package geo

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writeVarint(buf *bytes.Buffer, n int) {
	for n >= 0x80 {
		buf.WriteByte(byte(n&0x7f) | 0x80)
		n >>= 7
	}
	buf.WriteByte(byte(n))
}

// buildDat writes a category list whose outer framing matches the v2fly schema:
// repeated field 1, each entry a message whose field 1 is the category code.
// filler pads entries through an unknown high-numbered field, because field 2
// is the repeated Domain/CIDR message xray parses and so cannot carry padding.
func buildDat(codes []string, filler int) []byte {
	var buf bytes.Buffer
	for _, code := range codes {
		var body bytes.Buffer
		body.WriteByte(0x0a)
		writeVarint(&body, len(code))
		body.WriteString(code)
		if filler > 0 {
			body.Write([]byte{0xa2, 0x06}) // field 100, wire type 2: kept as unknown
			writeVarint(&body, filler)
			body.Write(make([]byte, filler))
		}
		buf.WriteByte(0x0a)
		writeVarint(&buf, body.Len())
		buf.Write(body.Bytes())
	}
	return buf.Bytes()
}

// writeDatEntry appends one framed entry carrying code followed by raw entry
// fields, so a test can shape the parsed part of the message.
func writeDatEntry(buf *bytes.Buffer, code string, fields []byte) {
	var body bytes.Buffer
	body.WriteByte(0x0a)
	writeVarint(&body, len(code))
	body.WriteString(code)
	body.Write(fields)
	buf.WriteByte(0x0a)
	writeVarint(buf, body.Len())
	buf.Write(body.Bytes())
}

func TestHasXrayCategory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(path, buildDat([]string{"DE", "US", "DE"}, 1200), 0644); err != nil {
		t.Fatal(err)
	}
	if !HasXrayCategory(path, "DE") {
		t.Fatal("IR category not found")
	}
	if HasXrayCategory(path, "ZZ") {
		t.Fatal("ZZ reported present")
	}
	cats := ListXrayCategories(path)
	if len(cats) != 3 || cats[0] != "DE" || cats[2] != "DE" {
		t.Fatalf("categories = %v", cats)
	}
}

func TestHasXrayCategoryRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(path, []byte("<html>error</html>"), 0644); err != nil {
		t.Fatal(err)
	}
	if HasXrayCategory(path, "DE") {
		t.Fatal("HTML payload reported as a category list")
	}
	if cats := ListXrayCategories(path); len(cats) != 0 {
		t.Fatalf("categories from garbage = %v", cats)
	}
}

func TestValidateSRS(t *testing.T) {
	if !ValidateSRS([]byte{'S', 'R', 'S', 0x01}) {
		t.Fatal("SRS magic not recognized")
	}
	if ValidateSRS([]byte("<ht")) || ValidateSRS([]byte("SR")) {
		t.Fatal("non-SRS payload accepted")
	}
}
func TestFindXrayCategoryMatchesCategoryPrefix(t *testing.T) {
	// v2fly's shared geosite.dat publishes country lists as "CATEGORY-DE";
	// a rule written as geosite:de must still resolve.
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, buildDat([]string{"0X0", "CATEGORY-DE", "CN"}, 900), 0644); err != nil {
		t.Fatal(err)
	}
	got, ok := FindXrayCategory(path, "de")
	if !ok || got != "CATEGORY-DE" {
		t.Fatalf("FindXrayCategory(ir) = %q, %v; want CATEGORY-DE, true", got, ok)
	}
	if got, ok := FindXrayCategory(path, "DE"); !ok || got != "CATEGORY-DE" {
		t.Fatalf("FindXrayCategory(IR) = %q, %v", got, ok)
	}
	if _, ok := FindXrayCategory(path, "zz"); ok {
		t.Fatal("zz reported present")
	}
}

func TestFindXrayCategoryPrefersExactSpelling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, buildDat([]string{"de"}, 900), 0644); err != nil {
		t.Fatal(err)
	}
	if got, ok := FindXrayCategory(path, "de"); !ok || got != "de" {
		t.Fatalf("FindXrayCategory(ir) = %q, %v; want ir", got, ok)
	}
}

func TestFindXrayCategoryUnreadableFile(t *testing.T) {
	if _, ok := FindXrayCategory(filepath.Join(t.TempDir(), "missing.dat"), "de"); ok {
		t.Fatal("missing file reported a category")
	}
}

// TestValidateXrayDatFileParsesEntryMessages pins the rest of xray's loader
// contract: after locating a code it proto.Unmarshals the entry, so the repeated
// Domain message carried in field 2 must itself be valid wire data.
func TestValidateXrayDatFileParsesEntryMessages(t *testing.T) {
	dir := t.TempDir()

	var fields bytes.Buffer
	fields.Write([]byte{0x12, 0x0f, 0x08, 0x01, 0x12, 0x0b}) // field 2: Domain{type: Plain, value: ...}
	fields.WriteString("example.com")
	fields.Write([]byte{0xa2, 0x06}) // field 100: padding the loader never parses
	writeVarint(&fields, 1200)
	fields.Write(make([]byte, 1200))

	var good bytes.Buffer
	writeDatEntry(&good, "CATEGORY-IR", fields.Bytes())
	path := filepath.Join(dir, "geosite.dat")
	if err := os.WriteFile(path, good.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateXrayDatFile(path); err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}
	if !HasXrayCategory(path, "CATEGORY-IR") {
		t.Fatal("CATEGORY-IR not found in a valid list")
	}

	// Same outer framing, but field 2 carries bytes protobuf cannot parse
	// (field number zero), which is exactly what aborted xray at startup.
	var badFields bytes.Buffer
	badFields.Write([]byte{0x12, 0x03, 0x00, 0x00, 0x00})
	badFields.Write([]byte{0xa2, 0x06})
	writeVarint(&badFields, 1200)
	badFields.Write(make([]byte, 1200))

	var bad bytes.Buffer
	writeDatEntry(&bad, "IR", badFields.Bytes())
	badPath := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(badPath, bad.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateXrayDatFile(badPath); err == nil {
		t.Fatal("entry with a malformed Domain message accepted")
	}
	if HasXrayCategory(badPath, "IR") {
		t.Fatal("malformed entry reported as a usable category")
	}
	if cats := ListXrayCategories(badPath); len(cats) != 0 {
		t.Fatalf("categories from malformed entry = %v", cats)
	}
}

// TestValidateXrayDatFileRequiresTheWholeList pins the provisioning contract: a
// .dat that starts with a valid entry but is truncated later is not usable,
// because xray refuses to start with it.
func TestValidateXrayDatFileRequiresTheWholeList(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(valid, buildDat([]string{"IR", "DE"}, 1200), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateXrayDatFile(valid); err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}

	truncated := filepath.Join(dir, "geosite.dat")
	full := buildDat([]string{"IR", "DE"}, 1200)
	if err := os.WriteFile(truncated, full[:len(full)-100], 0644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateXrayDatFile(truncated); err == nil {
		t.Fatal("truncated list accepted")
	}

	html := filepath.Join(dir, "html.dat")
	if err := os.WriteFile(html, bytes.Repeat([]byte("<html>error page</html>"), 100), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateXrayDatFile(html); err == nil {
		t.Fatal("HTML payload accepted as a category list")
	}
}
