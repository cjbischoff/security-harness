package model

import "testing"

// TestCampaignParity proves an ordered-Stages CampaignState marshals
// byte-identically to the Python golden, with stages emitted in insertion order
// (recon -> architecture -> threat-model -> prefilter), not sorted.
func TestCampaignParity(t *testing.T) {
	sha := "deadbeef"
	cs := CampaignState{
		PassNumber: 1,
		ActiveSHA:  &sha,
		Budget:     map[string]any{},
	}
	cs.Stages.Set("recon", "done")
	cs.Stages.Set("architecture", "done")
	cs.Stages.Set("threat-model", "done")
	cs.Stages.Set("prefilter", "done")

	got, err := MarshalCanonical(cs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertByteEqual(t, got, readGolden(t, "campaign.golden.json"))
}
