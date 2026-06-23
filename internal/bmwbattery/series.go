package bmwbattery

// GSeriesPlatforms is the set of BMW ISTA software-platform codes for CLAR /
// new-generation cars whose battery this module can read via G-series DIDs.
var GSeriesPlatforms = map[string]bool{
	"S15A": true, // CLAR gen 1   — 5 G30/G31/G32, 7 G11/G12, X3 G01/F97, X4 G02/F98, M5 F90
	"S15C": true, // CLAR gen 1+  — 5 LWB G38, X3M G08
	"S18A": true, // CLAR gen 2   — 3/4 G20–G26, 8 G14–G16, X5–X7 G05–G07, Z4 G29, M2–M4
	"G045": true, // electric     — iX G045/G046/G048
	"G070": true, // new gen      — 5 G60, 7 G70, M5 G84/G90
}

// IsGSeries reports whether an ISTA platform code is a G-series (CLAR) car this
// module supports. F-series codes ("F001"/"F010"/"F020"/"F025"/"F056") return
// false — their battery lives behind different DIDs (Read dispatches to readF).
func IsGSeries(platform string) bool {
	return GSeriesPlatforms[platform]
}
