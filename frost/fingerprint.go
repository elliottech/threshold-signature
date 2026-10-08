package frost

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// fpWords is the vocabulary for human-comparable fingerprints (64 words -> 6 bits each,
// 5 words -> 30 bits). Fingerprints are compared out-of-band, so collisions must be found
// before the ceremony completes to be useful to an attacker.
var fpWords = []string{
	"apple", "amber", "anchor", "aspen", "badge", "bamboo", "basil", "beacon",
	"birch", "bison", "breeze", "canyon", "carrot", "cedar", "cliff", "clover",
	"cobalt", "coral", "crane", "delta", "dune", "ember", "falcon", "fern",
	"fjord", "flint", "gecko", "ginger", "glade", "granite", "harbor", "hazel",
	"heron", "ivory", "jade", "juniper", "kelp", "lagoon", "lark", "lotus",
	"mango", "maple", "meadow", "nectar", "nickel", "ocean", "onyx", "orchid",
	"otter", "pebble", "pine", "plum", "quartz", "raven", "reef", "sable",
	"sage", "salmon", "sierra", "thistle", "tulip", "umber", "violet", "walnut",
}

// Fingerprint hashes a canonical payload into five human-comparable words.
func Fingerprint(payload string) string {
	h := sha256.Sum256([]byte(payload))
	words := make([]string, 5)
	for i := range words {
		words[i] = fpWords[binary.BigEndian.Uint16(h[i*2:])%uint16(len(fpWords))]
	}
	return strings.Join(words, "-")
}

// DkgParticipant is one row of the public DKG transcript used for fingerprinting.
type DkgParticipant struct {
	Idx         int
	Address     string
	AuthPk      string
	EncPk       string
	Commitments []string
	PoK         PoK
}

// DkgFingerprint digests the full public DKG transcript — policy, roster, every dealer's
// commitments and PoK — into five words. Participants read them to each other before signing;
// a server equivocating (showing different transcripts to different clients) produces different
// words.
func DkgFingerprint(room string, threshold, total int, allowed []string, parts []DkgParticipant) string {
	sorted := append([]DkgParticipant(nil), parts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Idx < sorted[j].Idx })
	var b strings.Builder
	fmt.Fprintf(&b, "dkg-fp/%s/%d/%d/%s", room, threshold, total, strings.Join(allowed, ","))
	for _, p := range sorted {
		fmt.Fprintf(&b, "/%d:%s:%s:%s:%s:%s:%s",
			p.Idx, strings.ToLower(p.Address), p.AuthPk, p.EncPk, strings.Join(p.Commitments, ","), p.PoK.R, p.PoK.Mu)
	}
	return Fingerprint(b.String())
}

// ProposalFingerprint digests a locked proposal — exact message, signer set, and every signer's
// nonce commitments — into five words compared out-of-band before partials are produced.
func ProposalFingerprint(room string, proposalID int64, message string, signers []int, commits []Commitment) string {
	set := append([]int(nil), signers...)
	sort.Ints(set)
	cs := append([]Commitment(nil), commits...)
	sort.Slice(cs, func(i, j int) bool { return cs[i].Idx < cs[j].Idx })
	var b strings.Builder
	fmt.Fprintf(&b, "proposal-fp/%s/%d/%s/%v", room, proposalID, message, set)
	for _, c := range cs {
		fmt.Fprintf(&b, "/%d:%s:%s", c.Idx, c.D, c.E)
	}
	return Fingerprint(b.String())
}
