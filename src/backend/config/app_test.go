package config

import (
	"testing"
	"time"

	"go.yaml.in/yaml/v2"
)

// TestSNISniffer_YAMLRoundtrip pins the wire format so the WebUI and the
// shipped config.yaml stay in sync with the runtime model.
func TestSNISniffer_YAMLRoundtrip(t *testing.T) {
	enabled := true
	queue := uint16(7)
	maxLen := uint32(2048)
	enableTLS := false
	enableHTTP := true
	enableHTTP2 := true
	ports := []uint16{443, 8443}
	addTTL := 2 * time.Hour

	in := &App{
		SNISniffer: &SNISniffer{
			Enabled:        &enabled,
			QueueNum:       &queue,
			MaxQueueLen:    &maxLen,
			EnableTLS:      &enableTLS,
			EnableHTTP:     &enableHTTP,
			EnableHTTP2:    &enableHTTP2,
			AllowedPorts:   &ports,
			AdditionalTTL:  &addTTL,
		},
	}

	out, err := yaml.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back App
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v\nyaml:\n%s", err, out)
	}

	if back.SNISniffer == nil {
		t.Fatal("SNISniffer lost across roundtrip")
	}
	if back.SNISniffer.Enabled == nil || *back.SNISniffer.Enabled != enabled {
		t.Errorf("Enabled = %v, want %v", back.SNISniffer.Enabled, enabled)
	}
	if back.SNISniffer.QueueNum == nil || *back.SNISniffer.QueueNum != queue {
		t.Errorf("QueueNum = %v, want %v", back.SNISniffer.QueueNum, queue)
	}
	if back.SNISniffer.MaxQueueLen == nil || *back.SNISniffer.MaxQueueLen != maxLen {
		t.Errorf("MaxQueueLen = %v, want %v", back.SNISniffer.MaxQueueLen, maxLen)
	}
	if back.SNISniffer.EnableTLS == nil || *back.SNISniffer.EnableTLS != enableTLS {
		t.Errorf("EnableTLS = %v, want %v", back.SNISniffer.EnableTLS, enableTLS)
	}
	if back.SNISniffer.AllowedPorts == nil || len(*back.SNISniffer.AllowedPorts) != 2 {
		t.Errorf("AllowedPorts roundtrip lost entries: %v", back.SNISniffer.AllowedPorts)
	}
	if back.SNISniffer.AdditionalTTL == nil || *back.SNISniffer.AdditionalTTL != addTTL {
		t.Errorf("AdditionalTTL = %v, want %v", back.SNISniffer.AdditionalTTL, addTTL)
	}
}

// TestSNISniffer_OmittedStaysNil confirms that leaving the sniffer block
// out of the YAML produces a nil pointer. LoadConfig treats nil as "keep
// default"; here we just verify the unmarshal side.
func TestSNISniffer_OmittedStaysNil(t *testing.T) {
	var back App
	if err := yaml.Unmarshal([]byte("httpWeb:\n  enabled: true\n"), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.SNISniffer != nil {
		t.Fatalf("SNISniffer should be nil when omitted; got %+v", back.SNISniffer)
	}
}

// TestSNISniffer_PartialOverride verifies that providing only a subset of
// fields leaves the rest as nil. LoadConfig then uses defaults for the
// nil fields via applyIfSet.
func TestSNISniffer_PartialOverride(t *testing.T) {
	raw := []byte("sniSniffer:\n  enabled: true\n  queueNum: 3\n")
	var back App
	if err := yaml.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.SNISniffer == nil {
		t.Fatal("SNISniffer is nil")
	}
	if back.SNISniffer.Enabled == nil || !*back.SNISniffer.Enabled {
		t.Errorf("Enabled = %v, want true", back.SNISniffer.Enabled)
	}
	if back.SNISniffer.QueueNum == nil || *back.SNISniffer.QueueNum != 3 {
		t.Errorf("QueueNum = %v, want 3", back.SNISniffer.QueueNum)
	}
	if back.SNISniffer.EnableTLS != nil {
		t.Errorf("EnableTLS = %v, want nil", back.SNISniffer.EnableTLS)
	}
}