package zgw

import (
	"encoding/csv"
	"os"
	"sort"
	"testing"
)

// seriesToChassis converts FA series codes (e.g. "G030", "F015") to our chassis
// form ("G30", "F15"): drop the middle '0'.
func seriesToChassis(series string) string {
	if len(series) == 4 && series[1] == '0' {
		return series[:1] + series[2:]
	}
	return series
}

// TestFAAccuracy runs decodeVIN against the FA ground-truth CSV (extracted from
// tests_FA_all) and reports chassis/platform accuracy. Skips when the CSV is
// absent (so it never runs in CI). Run: go test ./internal/zgw -run FAAccuracy -v
func TestFAAccuracy(t *testing.T) {
	f, err := os.Open("/tmp/fa_ground.csv")
	if err != nil {
		t.Skip("no /tmp/fa_ground.csv")
	}
	defer f.Close()
	r := csv.NewReader(f)
	recs, err := r.ReadAll()
	if err != nil || len(recs) < 2 {
		t.Fatalf("read csv: %v", err)
	}

	total, chassisOK := 0, 0
	platTotal, platOK := 0, 0
	type mm struct{ want, got string }
	chassisMiss := map[mm]int{}
	tk4ok, tk3ok := 0, 0 // how often an exact VIN[3:7]/[3:6] lookup would be unique-correct

	// Build FA-derived maps for "training" estimate.
	tk4chassis := map[string]map[string]int{} // VIN[3:7] -> chassis -> count
	for _, rec := range recs[1:] {
		vin, series, _, platform := rec[0], rec[1], rec[2], rec[3]
		if len(vin) < 17 {
			continue
		}
		wantCh := seriesToChassis(series)
		tk4 := vin[3:7]
		if tk4chassis[tk4] == nil {
			tk4chassis[tk4] = map[string]int{}
		}
		tk4chassis[tk4][wantCh]++
		_ = platform
	}

	for _, rec := range recs[1:] {
		vin, series, platform := rec[0], rec[1], rec[3]
		if len(vin) < 17 {
			continue
		}
		total++
		wantCh := seriesToChassis(series)
		gotCh, _, _, _, _ := decodeVIN(vin)
		if gotCh == wantCh {
			chassisOK++
		} else {
			chassisMiss[mm{wantCh, gotCh}]++
		}

		// Platform accuracy (only where FA provides an I-Step platform).
		if platform != "" {
			platTotal++
			if platformForChassis(gotCh) == platform {
				platOK++
			}
		}

		// "Trained" estimate: would an exact VIN[3:7] lookup be correct?
		// (correct = the most-common chassis for that type key equals wantCh)
		tk4 := vin[3:7]
		if best := topKey(tk4chassis[tk4]); best == wantCh {
			tk4ok++
		}
		_ = tk3ok
	}

	t.Logf("VINs: %d", total)
	t.Logf("CHASSIS  current heuristic: %d/%d = %.1f%%", chassisOK, total, 100*float64(chassisOK)/float64(total))
	t.Logf("CHASSIS  FA 4-char typeKey lookup (trained): %d/%d = %.1f%%", tk4ok, total, 100*float64(tk4ok)/float64(total))
	if platTotal > 0 {
		t.Logf("PLATFORM current (where FA has I-Step): %d/%d = %.1f%%", platOK, platTotal, 100*float64(platOK)/float64(platTotal))
	}

	// Top chassis mismatches.
	type e struct {
		m mm
		n int
	}
	var es []e
	for m, n := range chassisMiss {
		es = append(es, e{m, n})
	}
	sort.Slice(es, func(i, j int) bool { return es[i].n > es[j].n })
	t.Logf("--- top chassis mismatches (want -> got : count) ---")
	for i, x := range es {
		if i >= 20 {
			break
		}
		t.Logf("  %-5s -> %-5s : %d", x.m.want, x.m.got, x.n)
	}
}

func topKey(m map[string]int) string {
	best, bn := "", -1
	for k, n := range m {
		if n > bn {
			best, bn = k, n
		}
	}
	return best
}
