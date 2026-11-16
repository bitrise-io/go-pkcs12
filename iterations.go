package pkcs12

import (
	"crypto/x509/pkix"
	"errors"
)

// maxIterations is the total number of key derivation iterations a file may ask for across its
// MAC and all of its encrypted parts. The counts come from the file itself, so without a limit a
// file of a hundred bytes can keep a decoder busy for as long as it likes. Common tools write
// between 2,000 and 600,000 iterations per part.
const maxIterations = 5_000_000

// ErrTooManyIterations is returned when decoding a file would take more key derivation
// iterations than this package is willing to run.
var ErrTooManyIterations = errors.New("pkcs12: too many key derivation iterations")

type iterationBudget struct {
	remaining int
}

func newIterationBudget() *iterationBudget {
	return &iterationBudget{remaining: maxIterations}
}

func (b *iterationBudget) spend(iterations int) error {
	if iterations > b.remaining {
		return ErrTooManyIterations
	}
	if iterations > 0 {
		b.remaining -= iterations
	}
	return nil
}

// spendForKeyBags charges for every shrouded key bag up front, including the ones a caller ends
// up not decrypting, because the callers decrypt them one at a time after the bags are returned.
func (b *iterationBudget) spendForKeyBags(bags []safeBag) error {
	for _, bag := range bags {
		if !bag.Id.Equal(oidPKCS8ShroundedKeyBag) {
			continue
		}

		var keyInfo encryptedPrivateKeyInfo
		if err := unmarshal(bag.Value.Bytes, &keyInfo); err != nil {
			continue
		}
		if err := b.spend(iterationsFor(keyInfo.AlgorithmIdentifier)); err != nil {
			return err
		}
	}
	return nil
}

// iterationsFor returns the iteration count a password-based encryption algorithm asks for. It
// is zero for parameters pbeCipherFor rejects, since no key is derived for those.
func iterationsFor(algorithm pkix.AlgorithmIdentifier) int {
	switch {
	case algorithm.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC),
		algorithm.Algorithm.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		var params pbeParams
		if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
			return 0
		}
		return params.Iterations
	case algorithm.Algorithm.Equal(oidPBES2):
		var params pbes2Params
		if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
			return 0
		}
		if !params.Kdf.Algorithm.Equal(oidPBKDF2) {
			return 0
		}
		var kdfParams pbkdf2Params
		if err := unmarshal(params.Kdf.Parameters.FullBytes, &kdfParams); err != nil {
			return 0
		}
		return kdfParams.Iterations
	default:
		return 0
	}
}
