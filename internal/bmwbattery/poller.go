package bmwbattery

import (
	"context"
	"time"
)

// Poll reads the battery from host every interval and invokes fn with each
// result (the first read fires immediately, not after the first interval). It
// blocks until ctx is cancelled, so call it in its own goroutine:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	go bmwbattery.Poll(ctx, "169.254.14.38", time.Minute, func(st *bmwbattery.Status, err error) {
//	    if err != nil { return }       // keep showing the previous value
//	    fmt.Println(st)                // 🔋 62%  ·  V: 13.06  ·  Ageing 58%
//	})
//	// … cancel() to stop.
func Poll(ctx context.Context, host string, interval time.Duration, fn func(*Status, error)) {
	if interval <= 0 {
		interval = time.Minute
	}
	tick := func() {
		st, err := Read(host)
		fn(st, err)
	}
	tick() // immediate first read

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// StickyPoll is like Poll but holds the last good value of each field across
// failed or partial reads, so a no-response cycle (or a single DID that didn't
// answer) never blanks a field. fn receives the merged, sticky status.
func StickyPoll(ctx context.Context, host string, interval time.Duration, fn func(*Status)) {
	var held *Status
	Poll(ctx, host, interval, func(st *Status, err error) {
		held = merge(held, st)
		if held != nil {
			fn(held)
		}
	})
}

// merge folds a fresh reading into the held one, keeping each field's last good
// value when this read didn't get it.
func merge(held, fresh *Status) *Status {
	if held == nil {
		held = &Status{}
	}
	if fresh == nil {
		return held
	}
	if fresh.HasSoC {
		held.SoCPercent, held.HasSoC = fresh.SoCPercent, true
	}
	if fresh.HasVoltage {
		held.VoltageV, held.HasVoltage = fresh.VoltageV, true
	}
	if fresh.HasAgeing {
		held.AgeingPercent, held.HasAgeing = fresh.AgeingPercent, true
	}
	return held
}
