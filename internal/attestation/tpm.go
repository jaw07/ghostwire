package attestation

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"sort"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
)

// TPM_GENERATED_VALUE prefixes every structure the TPM signs with an AK. Its
// presence (enforced by DecodeAttestationData) is what proves the quote was
// produced inside the TPM rather than forged in software.
const tpmGeneratedValue = 0xff544347

// TPMPolicy is the out-of-band trust anchor for a node's TPM attestation. It is
// registered with the verifier ahead of time (analogous to a trusted binary
// hash): the AK public key authenticates the quote, and the expected PCR values
// pin the node to a known-good measured-boot state.
type TPMPolicy struct {
	// AKPublic is the trusted Attestation Key public key (*rsa.PublicKey or
	// *ecdsa.PublicKey). The quote signature must verify against this key.
	AKPublic crypto.PublicKey

	// ExpectedPCRs maps PCR index to its expected value in the PCRBank. Every
	// PCR the quote selects must be present here, or verification fails closed.
	ExpectedPCRs map[int][]byte

	// PCRBank is the hash algorithm of the PCR bank the expected values belong
	// to (e.g. crypto.SHA256). It must match the bank named in the quote.
	PCRBank crypto.Hash
}

// SetTPMPolicy registers (or replaces) the trusted TPM attestation policy for a
// node. Without a registered policy, TPM claims for that node fail closed.
func (v *Verifier) SetTPMPolicy(nodeID string, policy *TPMPolicy) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tpmPolicies[nodeID] = policy
}

// RemoveTPMPolicy removes a node's TPM attestation policy.
func (v *Verifier) RemoveTPMPolicy(nodeID string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.tpmPolicies, nodeID)
}

// verifyTPMQuote performs full TPM 2.0 quote verification:
//  1. decode the TPMS_ATTEST quote (the magic prefix proves TPM origin),
//  2. confirm it is a quote bound to the challenge nonce (freshness),
//  3. verify the AK signature over the quote against the trusted policy key,
//  4. recompute the expected PCR digest and compare it to the quoted digest.
//
// Any failure returns an error so the caller rejects the claim.
func (v *Verifier) verifyTPMQuote(claim *Claim) error {
	v.mu.RLock()
	policy := v.tpmPolicies[claim.NodeID]
	v.mu.RUnlock()

	if policy == nil {
		return fmt.Errorf("no TPM policy registered for node %q", claim.NodeID)
	}
	if policy.AKPublic == nil {
		return errors.New("TPM policy has no AK public key")
	}
	if len(claim.TPMSig) == 0 {
		return errors.New("TPM signature missing")
	}

	// 1. Decode the attestation structure. DecodeAttestationData rejects any
	// blob without the TPM_GENERATED_VALUE magic, so a software-forged buffer
	// cannot masquerade as a quote.
	attest, err := tpm2.DecodeAttestationData(claim.TPMQuote)
	if err != nil {
		return fmt.Errorf("malformed quote: %w", err)
	}
	if attest.Magic != tpmGeneratedValue {
		return errors.New("quote not TPM-generated")
	}
	if attest.Type != tpm2.TagAttestQuote || attest.AttestedQuoteInfo == nil {
		return errors.New("attestation is not a quote")
	}

	// 2. Freshness: the quote's extraData must carry the challenge nonce we
	// issued, binding this quote to this verification round.
	if !bytes.Equal(attest.ExtraData, claim.Nonce[:]) {
		return errors.New("quote nonce mismatch (not bound to challenge)")
	}

	// 3. Verify the AK signature over the exact quote bytes.
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(claim.TPMSig))
	if err != nil {
		return fmt.Errorf("malformed signature: %w", err)
	}
	sigHash, err := verifyAKSignature(policy.AKPublic, claim.TPMQuote, sig)
	if err != nil {
		return err
	}

	// 4. PCR state: recompute the digest the TPM would have produced from the
	// trusted expected PCR values and compare it to the signed quote digest.
	expectedDigest, err := expectedPCRDigest(policy, attest.AttestedQuoteInfo.PCRSelection, sigHash)
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedDigest, attest.AttestedQuoteInfo.PCRDigest) {
		return errors.New("PCR digest mismatch (node not in expected state)")
	}

	return nil
}

// verifyAKSignature checks the TPM signature over the quote bytes using the
// trusted AK public key, returning the hash algorithm used (needed to recompute
// the PCR digest, which the TPM computes with the same hash).
func verifyAKSignature(pub crypto.PublicKey, quote []byte, sig *tpm2.Signature) (crypto.Hash, error) {
	switch sig.Alg {
	case tpm2.AlgRSASSA, tpm2.AlgRSAPSS:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return 0, errors.New("AK is not an RSA key but signature is RSA")
		}
		h, err := sig.RSA.HashAlg.Hash()
		if err != nil {
			return 0, fmt.Errorf("unsupported RSA hash: %w", err)
		}
		digest := hashBytes(h, quote)
		if sig.Alg == tpm2.AlgRSAPSS {
			if err := rsa.VerifyPSS(rsaPub, h, digest, sig.RSA.Signature, nil); err != nil {
				return 0, fmt.Errorf("RSA-PSS signature invalid: %w", err)
			}
		} else {
			if err := rsa.VerifyPKCS1v15(rsaPub, h, digest, sig.RSA.Signature); err != nil {
				return 0, fmt.Errorf("RSA signature invalid: %w", err)
			}
		}
		return h, nil

	case tpm2.AlgECDSA:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return 0, errors.New("AK is not an ECDSA key but signature is ECDSA")
		}
		h, err := sig.ECC.HashAlg.Hash()
		if err != nil {
			return 0, fmt.Errorf("unsupported ECDSA hash: %w", err)
		}
		digest := hashBytes(h, quote)
		if !ecdsa.Verify(ecPub, digest, sig.ECC.R, sig.ECC.S) {
			return 0, errors.New("ECDSA signature invalid")
		}
		return h, nil

	default:
		return 0, fmt.Errorf("unsupported signature algorithm 0x%x", sig.Alg)
	}
}

// expectedPCRDigest recomputes the digest the TPM signs in a quote: the named
// hash over the concatenation of the selected PCR values, in ascending index
// order. Every selected PCR must have a trusted expected value.
func expectedPCRDigest(policy *TPMPolicy, sel tpm2.PCRSelection, sigHash crypto.Hash) ([]byte, error) {
	bankAlg, err := tpm2.HashToAlgorithm(policy.PCRBank)
	if err != nil {
		return nil, fmt.Errorf("unsupported PCR bank hash: %w", err)
	}
	if sel.Hash != bankAlg {
		return nil, fmt.Errorf("quote PCR bank 0x%x does not match policy bank 0x%x", sel.Hash, bankAlg)
	}
	if len(sel.PCRs) == 0 {
		return nil, errors.New("quote selects no PCRs")
	}

	indices := append([]int(nil), sel.PCRs...)
	sort.Ints(indices)

	var concat []byte
	for _, idx := range indices {
		val, ok := policy.ExpectedPCRs[idx]
		if !ok {
			return nil, fmt.Errorf("no expected value for selected PCR %d", idx)
		}
		concat = append(concat, val...)
	}
	return hashBytes(sigHash, concat), nil
}

// hashBytes returns h(data) for an already-imported crypto.Hash.
func hashBytes(h crypto.Hash, data []byte) []byte {
	hasher := h.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}
