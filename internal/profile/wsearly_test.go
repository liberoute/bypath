package profile

import "testing"

func TestSplitWSPathEarlyData(t *testing.T) {
	cases := []struct {
		in       string
		wantPath string
		wantED   int
	}{
		{"/Sudo_Network?ed=2560", "/Sudo_Network", 2560},
		{"/ws", "/ws", 0},
		{"", "", 0},
		{"/ws?token=abc&ed=2048", "/ws?token=abc", 2048},
		{"/ws?ed=2048&token=abc", "/ws?token=abc", 2048},
		{"/ws?ed=0", "/ws?ed=0", 0},
		{"/ws?ed=abc", "/ws?ed=abc", 0},
		{"/ws?ed=", "/ws?ed=", 0},
		{"/ws?token=abc", "/ws?token=abc", 0},
		{"/ws?ed=2560#frag", "/ws?ed=2560#frag", 0},
	}
	for _, c := range cases {
		path, ed := SplitWSPathEarlyData(c.in)
		if path != c.wantPath || ed != c.wantED {
			t.Errorf("SplitWSPathEarlyData(%q) = (%q,%d), want (%q,%d)", c.in, path, ed, c.wantPath, c.wantED)
		}
	}
}

func TestParseWSPathEarlyDataNormalized(t *testing.T) {
	uri := "vless://4e309896-c656-4d25-811f-486cad6da138@cdn.example.com:443" +
		"?encryption=none&fp=firefox&host=cdn.example.com" +
		"&path=%2Fws%3Fed%3D2560&security=tls&sni=cdn.example.com&type=ws#ev"
	link, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}
	if link.Path != "/ws" {
		t.Errorf("path: got %q want /ws", link.Path)
	}
	if link.WSMaxEarlyData != 2560 {
		t.Errorf("ws_max_early_data: got %d want 2560", link.WSMaxEarlyData)
	}
	if link.WSEarlyDataHeader != "" {
		t.Errorf("ws_early_data_header: got %q want empty (engine default)", link.WSEarlyDataHeader)
	}
	if err := ValidateParsedLink(link); err != nil {
		t.Fatalf("ValidateParsedLink: %v", err)
	}
}
