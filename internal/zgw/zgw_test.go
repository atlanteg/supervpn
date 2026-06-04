package zgw

import "testing"

func TestDecodeVINChassis(t *testing.T) {
	cases := []struct {
		vin         string
		wantChassis string
		note        string
	}{
		// Reported bug: VIN[3]='5' with MY 'L'(2020) is a G20 3 Series (330i
		// xDrive), not the 5 Series F10. VIN[9]='L' is the ISO model-year char
		// (VIN[8]='X' is the check digit), which the decoder must read — not
		// VIN[10]='F' (the plant code).
		{"WBA5R7C0XLFH66853", "G20", "G20 330i xDrive (was wrongly F10)"},
		// Pre-2019 '5' (model year 'D'=2013) is still the 5 Series F10.
		{"WBA5A1000DC123456", "F10", "old 5 Series stays F10"},
	}
	for _, c := range cases {
		chassis, _, _, _, _ := decodeVIN(c.vin)
		if chassis != c.wantChassis {
			t.Errorf("decodeVIN(%s) chassis = %q, want %q (%s)", c.vin, chassis, c.wantChassis, c.note)
		}
	}
}

func TestG20PlatformIsS18A(t *testing.T) {
	if chassisPlatform["G20"] != "S18A" {
		t.Errorf("G20 platform = %q, want S18A", chassisPlatform["G20"])
	}
}
