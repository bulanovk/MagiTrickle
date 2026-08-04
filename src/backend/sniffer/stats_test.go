package sniffer

import (
	"testing"
	"time"
)

func TestCounters_RecordPacket_Hit(t *testing.T) {
	c := &counters{startedAt: time.Now()}
	c.recordPacket(true, false, false)
	c.recordPacket(true, false, false)
	s := c.snapshot()
	if s.PacketsTotal != 2 {
		t.Errorf("PacketsTotal = %d, want 2", s.PacketsTotal)
	}
	if s.HitsTotal != 2 {
		t.Errorf("HitsTotal = %d, want 2", s.HitsTotal)
	}
	if s.MissesTotal != 0 || s.ParseFailures != 0 {
		t.Errorf("untouched counters not zero: misses=%d failures=%d", s.MissesTotal, s.ParseFailures)
	}
}

func TestCounters_RecordPacket_MissAndFailure(t *testing.T) {
	c := &counters{startedAt: time.Now()}
	c.recordPacket(false, true, false)
	c.recordPacket(false, false, true)
	c.recordPacket(false, false, true)
	c.recordPacket(false, false, true)
	s := c.snapshot()
	if s.MissesTotal != 1 {
		t.Errorf("MissesTotal = %d, want 1", s.MissesTotal)
	}
	if s.ParseFailures != 3 {
		t.Errorf("ParseFailures = %d, want 3", s.ParseFailures)
	}
	if s.PacketsTotal != 4 {
		t.Errorf("PacketsTotal = %d, want 4", s.PacketsTotal)
	}
}

func TestCounters_SnapshotZeroOnFresh(t *testing.T) {
	c := &counters{startedAt: time.Now()}
	s := c.snapshot()
	if s.PacketsTotal != 0 || s.HitsTotal != 0 || s.MissesTotal != 0 || s.ParseFailures != 0 {
		t.Errorf("fresh counters not zero: %+v", s)
	}
	if !s.Active {
		t.Error("Active = false, want true (counters struct only used by active sniffer)")
	}
	if s.StartedAt.IsZero() {
		t.Error("StartedAt is zero")
	}
}

func TestCounters_PpsZeroBeforeFirstSecondRollover(t *testing.T) {
	c := &counters{startedAt: time.Now()}
	c.recordPacket(true, false, false)
	c.recordPacket(true, false, false)
	s := c.snapshot()
	if s.PacketsPerSec != 0 {
		t.Errorf("PacketsPerSec = %f, want 0 (no second rollover yet)", s.PacketsPerSec)
	}
	if s.PacketsTotal != 2 {
		t.Errorf("PacketsTotal = %d, want 2", s.PacketsTotal)
	}
}

func TestCounters_PpsReflectsCompletedSecond(t *testing.T) {
	c := &counters{startedAt: time.Now()}
	// Simulate three packets in second N, then roll over to second N+1
	// by bumping ppsCurrent backwards.
	c.ppsMu.Lock()
	c.ppsCurrent = time.Now().Unix()
	c.ppsMu.Unlock()
	c.recordPacket(true, false, false)
	c.recordPacket(true, false, false)
	c.recordPacket(true, false, false)
	// Force the next recordPacket to commit ppsBucket → ppsLastFull.
	c.ppsMu.Lock()
	c.ppsCurrent = time.Now().Unix() - 1
	c.ppsMu.Unlock()
	c.recordPacket(true, false, false)
	s := c.snapshot()
	if s.PacketsPerSec != 3 {
		t.Errorf("PacketsPerSec = %f, want 3 (packets from prior second)", s.PacketsPerSec)
	}
	if s.PacketsTotal != 4 {
		t.Errorf("PacketsTotal = %d, want 4", s.PacketsTotal)
	}
}