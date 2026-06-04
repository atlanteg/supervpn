package bmwzgw

import (
	"encoding/csv"
	_ "embed"
	"strconv"
	"strings"
)

//go:embed bmw_types.csv
var bmwTypesCSV string

// VINVariant holds enriched data from the scraped BMW type database for one model variant.
type VINVariant struct {
	FamilyCode string // base family code, e.g. "G30"
	Model      string // model name without chassis prefix, e.g. "530i xDrive"
	Engine     string // BMW engine code, e.g. "B57D30O0"
	PowerKW    int    // engine output in kW, e.g. 195
	Drivetrain string // "Rear-Wheel Drive" | "All Wheel-Drive" | "Front-Wheel Drive"
	Body       string // "Sedan" | "Touring" | "Coupe" | "Sports Activity Vehicle" | …
	Steering   string // "left" | "right"
	Region     string // "Europe" | "USA" | …
}

// variantIndex maps base family code → all known variants (from the embedded CSV).
// Populated once at package init.
var variantIndex map[string][]VINVariant

func init() {
	variantIndex = parseVariantCSV(bmwTypesCSV)
}

// baseFamilyCode strips generation/facelift suffixes: "G30 (MUE)" → "G30".
func baseFamilyCode(code string) string {
	if i := strings.Index(code, " ("); i >= 0 {
		return code[:i]
	}
	return code
}

func parseVariantCSV(data string) map[string][]VINVariant {
	idx := make(map[string][]VINVariant)
	r := csv.NewReader(strings.NewReader(data))
	r.LazyQuotes = true
	r.TrimLeadingSpace = true

	header, err := r.Read()
	if err != nil {
		return idx
	}

	// Build column index, stripping UTF-8 BOM from first header name.
	colMap := make(map[string]int)
	for i, h := range header {
		h = strings.TrimSpace(h)
		h = strings.TrimPrefix(h, "\xef\xbb\xbf") // BOM
		colMap[h] = i
	}

	get := func(rec []string, name string) string {
		i, ok := colMap[name]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}

	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		if get(rec, "record_kind") != "variant" {
			continue
		}

		fam := baseFamilyCode(get(rec, "family_code"))
		model := get(rec, "model")
		if fam == "" || model == "" {
			continue
		}

		powerKW := 0
		if p := get(rec, "power"); strings.HasSuffix(p, "kW") {
			powerKW, _ = strconv.Atoi(strings.TrimSuffix(p, "kW"))
		}

		idx[fam] = append(idx[fam], VINVariant{
			FamilyCode: fam,
			Model:      model,
			Engine:     get(rec, "engine"),
			PowerKW:    powerKW,
			Drivetrain: get(rec, "drivetrain"),
			Body:       get(rec, "chassis"), // DB calls it "chassis"; we call it body type
			Steering:   get(rec, "steering"),
			Region:     get(rec, "region"),
		})
	}
	return idx
}

// lookupVariant finds the best-matching DB entry for the given chassis code,
// drivetrain string, and engine-suffix substring (e.g. "20d", "30i", "xDrive20d").
//
// Matching rules:
//  1. drivetrain must match exactly.
//  2. engSuffix (case-insensitive) must appear in the variant's model name.
//  3. Among candidates: Europe > other regions, left-hand drive > right.
//
// Returns nil when no suitable variant exists (e.g. G20 not in DB, or suffix mismatch).
func lookupVariant(chassisCode, drivetrain, engSuffix string) *VINVariant {
	variants, ok := variantIndex[chassisCode]
	if !ok {
		return nil
	}

	engLower := strings.ToLower(engSuffix)
	var candidates []VINVariant
	for _, v := range variants {
		if v.Drivetrain != drivetrain {
			continue
		}
		if engSuffix != "" && !strings.Contains(strings.ToLower(v.Model), engLower) {
			continue
		}
		candidates = append(candidates, v)
	}
	if len(candidates) == 0 {
		return nil
	}

	// Score each candidate: prefer Europe + left-hand drive.
	score := func(v VINVariant) int {
		s := 0
		if strings.ToLower(v.Region) == "europe" {
			s += 2
		}
		if v.Steering == "left" {
			s += 1
		}
		return s
	}
	best := candidates[0]
	bestScore := score(best)
	for _, c := range candidates[1:] {
		if s := score(c); s > bestScore {
			best = c
			bestScore = s
		}
	}
	return &best
}
