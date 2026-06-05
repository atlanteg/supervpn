# BMW VIN decoder

How supervpn turns a BMW VIN (read from the ZGW over ENET) into a chassis,
model and ISTA platform — and how to retrain it on fresh data.

The decoder lives in **two places, kept in sync**:

| Location | What | Used by |
|---|---|---|
| `internal/zgw/` | built-in decoder | the VPN clients (CLI, GUI, seema) — BMW detection in the app |
| `standalone/bmwzgw/` | standalone Go module (`github.com/atlanteg/bmwzgw`, own `go.mod`) | separate third-party integrations |

The server does not decode VINs.

---

## How decoding works

`decodeVIN(vin)` resolves in this order:

1. **FA-learned 4-char type key** — `VIN[3:7]` is looked up in `faTypeKeys`
   (generated from real BMW FA backups). The 4-char type key is ~98% unique per
   chassis, so this is authoritative: it yields chassis, model designation
   (e.g. `330i`) and xDrive. This covers ~725 known type keys.
2. **Single-char heuristic** — for type keys not in the FA table, falls back to
   the `VIN[3]` tables (`bmwTypeKeys` + `gseriesIntroMY`/`fseriesAltKeys` for
   generation disambiguation via the `VIN[9]` ISO model-year char).

The ISTA **platform** comes from `platformForChassis(chassis)`: the FA-learned
`faChassisPlatform` (real I-Step data) first, then the hand-curated
`chassisPlatform`.

### Accuracy (measured on the FA training set)

| | single-char heuristic only | with FA tables |
|---|---|---|
| chassis | ~43% | **~99.6%** |
| platform | ~63% | **~99.7%** |

Example: `WBA5R7C0XLFH66853` → **G20 330i xDrive / S18A** (was wrongly `F10 535d`).

### Generated files (do not hand-edit)

- `fa_typekeys.go` — `VIN[3:7] → {chassis, model, xdrive}` (~725 keys)
- `fa_platform.go` — `chassis → ISTA platform` (~77 chassis)

Both exist in `internal/zgw/` (package `zgw`) and `standalone/bmwzgw/`
(package `bmwzgw`), generated identically.

---

## Retraining (дообучение)

Ground truth comes from BMW **FA (Fahrzeugauftrag) backups** — XML files that
contain `vinLong`, `series` (chassis), the 4-char `typeKey` (= `VIN[3:7]`), the
model name and the I-Step (shipment) platform.

To retrain after collecting more FA backups:

```bash
# 1. Drop the FA data anywhere — a directory of *.xml and/or *.zip archives.
#    (The committed example lived in ./tests_FA_all — gitignored, not shipped.)

# 2. Regenerate both packages' tables from it:
python3 tools/vin-retrain/retrain.py PATH_TO_FA_DIR
gofmt -w internal/zgw/fa_*.go standalone/bmwzgw/fa_*.go

# 3. Verify accuracy against the same data (uses /tmp/fa_ground.csv written in step 2):
go test ./internal/zgw -run FAAccuracy -v
#   prints chassis/platform accuracy + the top remaining mismatches

# 4. Build + commit the regenerated fa_typekeys.go / fa_platform.go (both dirs).
go build ./...
```

The script (`tools/vin-retrain/retrain.py`):
- reads every `*.xml` (including inside `*.zip`) under the given path,
- dedups by VIN, learns `VIN[3:7] → model` and `chassis → platform` (most common
  value per key),
- writes `fa_typekeys.go` + `fa_platform.go` into **both** `internal/zgw/` and
  `standalone/bmwzgw/`,
- writes `/tmp/fa_ground.csv` for the accuracy harness.

`internal/zgw/analyze_fa_test.go` is the accuracy harness; it skips cleanly when
`/tmp/fa_ground.csv` is absent, so it never runs in CI.

The raw FA archive is **not** committed (gitignored) — only the distilled Go
tables are. Keep FA backups private if they contain real customer VINs.
