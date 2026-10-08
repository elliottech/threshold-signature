package frost

import "testing"

func TestFingerprintDeterministicAndDistinct(t *testing.T) {
	parts := []DkgParticipant{
		{Idx: 2, Address: "0xB", AuthPk: "a2", EncPk: "e2", Commitments: []string{"c2"}, PoK: PoK{R: "r2", Mu: "m2"}},
		{Idx: 1, Address: "0xA", AuthPk: "a1", EncPk: "e1", Commitments: []string{"c1"}, PoK: PoK{R: "r1", Mu: "m1"}},
	}
	fp := DkgFingerprint("room", 2, 3, nil, parts)
	// Order-independent: same transcript in any order gives the same words.
	if got := DkgFingerprint("room", 2, 3, nil, []DkgParticipant{parts[1], parts[0]}); got != fp {
		t.Fatalf("order changed fingerprint: %s vs %s", got, fp)
	}
	if got := DkgFingerprint("room", 3, 3, nil, parts); got == fp {
		t.Fatal("altered threshold did not change fingerprint")
	}
	if got := DkgFingerprint("room", 2, 3, []string{"0xa"}, parts); got == fp {
		t.Fatal("altered roster did not change fingerprint")
	}

	commits := []Commitment{{Idx: 1, D: "d1", E: "e1"}, {Idx: 3, D: "d3", E: "e3"}}
	pfp := ProposalFingerprint("room", 7, "msg", []int{1, 3}, commits)
	if got := ProposalFingerprint("room", 7, "msg", []int{3, 1},
		[]Commitment{commits[1], commits[0]}); got != pfp {
		t.Fatal("proposal fingerprint not order-independent")
	}
	if got := ProposalFingerprint("room", 7, "other", []int{1, 3}, commits); got == pfp {
		t.Fatal("altered message did not change proposal fingerprint")
	}
	if got := ProposalFingerprint("room", 7, "msg", []int{1, 2}, commits); got == pfp {
		t.Fatal("altered signer set did not change proposal fingerprint")
	}
}
