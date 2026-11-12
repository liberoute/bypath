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

func buildDat(codes []string, filler int) []byte {
	var buf bytes.Buffer
	for _, code := range codes {
		var body bytes.Buffer
		body.WriteByte(0x0a)
		writeVarint(&body, len(code))
		body.WriteString(code)
		if filler > 0 {
			body.WriteByte(0x12)
			writeVarint(&body, filler)
			body.Write(make([]byte, filler))
		}
		buf.WriteByte(0x0a)
		writeVarint(&buf, body.Len())
		buf.Write(body.Bytes())
	}
	return buf.Bytes()
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
