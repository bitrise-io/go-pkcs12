package pkcs12

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math"
	"testing"
	"time"
)

const testPassword = "password"

func mustMarshal(t *testing.T, value interface{}) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func explicitContent(content []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: content}
}

func pbeAlgorithm(t *testing.T, iterations int) pkix.AlgorithmIdentifier {
	t.Helper()
	algorithm := pkix.AlgorithmIdentifier{Algorithm: oidPBEWithSHAAnd3KeyTripleDESCBC}
	algorithm.Parameters.FullBytes = mustMarshal(t, pbeParams{Salt: []byte("saltsalt"), Iterations: iterations})
	return algorithm
}

func pbes2Algorithm(t *testing.T, iterations int) pkix.AlgorithmIdentifier {
	t.Helper()
	kdf := pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2}
	kdf.Parameters.FullBytes = mustMarshal(t, pbkdf2Params{
		Salt:       asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("saltsalt")},
		Iterations: iterations,
		Prf:        pkix.AlgorithmIdentifier{Algorithm: oidHmacWithSHA256},
	})
	scheme := pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC}
	scheme.Parameters.FullBytes = mustMarshal(t, make([]byte, 16))

	algorithm := pkix.AlgorithmIdentifier{Algorithm: oidPBES2}
	algorithm.Parameters.FullBytes = mustMarshal(t, pbes2Params{Kdf: kdf, EncryptionScheme: scheme})
	return algorithm
}

func encryptedSafe(t *testing.T, algorithm pkix.AlgorithmIdentifier) contentInfo {
	t.Helper()
	var data encryptedData
	data.EncryptedContentInfo.ContentType = oidDataContentType
	data.EncryptedContentInfo.ContentEncryptionAlgorithm = algorithm
	data.EncryptedContentInfo.EncryptedContent = make([]byte, 16)
	return contentInfo{ContentType: oidEncryptedDataContentType, Content: explicitContent(mustMarshal(t, data))}
}

func keyBagSafe(t *testing.T, algorithms ...pkix.AlgorithmIdentifier) contentInfo {
	t.Helper()
	var bags []safeBag
	for _, algorithm := range algorithms {
		keyInfo := encryptedPrivateKeyInfo{AlgorithmIdentifier: algorithm, EncryptedData: make([]byte, 16)}
		bags = append(bags, safeBag{Id: oidPKCS8ShroundedKeyBag, Value: explicitContent(mustMarshal(t, keyInfo))})
	}
	return contentInfo{ContentType: oidDataContentType, Content: explicitContent(mustMarshal(t, mustMarshal(t, bags)))}
}

// pfxWith builds a PFX whose MAC is valid for testPassword unless macIterations is over the limit.
func pfxWith(t *testing.T, macIterations int, authenticatedSafe ...contentInfo) []byte {
	t.Helper()
	authenticatedSafeBytes := mustMarshal(t, authenticatedSafe)

	var pfx pfxPdu
	pfx.Version = 3
	pfx.MacData.Mac.Algorithm.Algorithm = oidSHA1
	pfx.MacData.MacSalt = []byte("saltsalt")
	pfx.MacData.Iterations = macIterations
	if macIterations <= maxIterations {
		password, err := bmpStringZeroTerminated(testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if err := computeMac(&pfx.MacData, authenticatedSafeBytes, password); err != nil {
			t.Fatal(err)
		}
	} else {
		pfx.MacData.Mac.Digest = make([]byte, 20)
	}
	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content = explicitContent(mustMarshal(t, authenticatedSafeBytes))
	return mustMarshal(t, pfx)
}

func decodeKeystoreWithin(t *testing.T, limit time.Duration, pfx []byte) error {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		_, _, err := DecodeKeystore(pfx, testPassword, "alias", testPassword)
		result <- err
	}()

	select {
	case err := <-result:
		return err
	case <-time.After(limit):
		t.Fatalf("decoding was still running after %s", limit)
		return nil
	}
}

func TestDecodeRejectsExcessiveIterations(t *testing.T) {
	tests := map[string][]byte{
		"MAC":                            pfxWith(t, math.MaxInt64),
		"encrypted safe":                 pfxWith(t, 1, encryptedSafe(t, pbeAlgorithm(t, math.MaxInt64))),
		"encrypted safe using PBES2":     pfxWith(t, 1, encryptedSafe(t, pbes2Algorithm(t, math.MaxInt64))),
		"key bag":                        pfxWith(t, 1, keyBagSafe(t, pbeAlgorithm(t, math.MaxInt64))),
		"key bag using PBES2":            pfxWith(t, 1, keyBagSafe(t, pbes2Algorithm(t, math.MaxInt64))),
		"key bag one over the limit":     pfxWith(t, 1, keyBagSafe(t, pbeAlgorithm(t, maxIterations))),
		"parts adding up over the limit": pfxWith(t, 1, keyBagSafe(t, pbeAlgorithm(t, maxIterations/2), pbeAlgorithm(t, maxIterations/2))),
		"parts overflowing the total":    pfxWith(t, 1, keyBagSafe(t, pbeAlgorithm(t, math.MaxInt64), pbeAlgorithm(t, math.MaxInt64))),
	}
	for name, pfx := range tests {
		t.Run(name, func(t *testing.T) {
			err := decodeKeystoreWithin(t, 5*time.Second, pfx)

			if !errors.Is(err, ErrTooManyIterations) {
				t.Fatalf("expected ErrTooManyIterations, got: %v", err)
			}
		})
	}
}

func TestDecodeAcceptsIterationsWithinTheLimit(t *testing.T) {
	pfx := pfxWith(t, 2048, keyBagSafe(t, pbeAlgorithm(t, 2048), pbes2Algorithm(t, 2048)))

	err := decodeKeystoreWithin(t, 5*time.Second, pfx)

	if errors.Is(err, ErrTooManyIterations) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIterationBudget(t *testing.T) {
	budget := newIterationBudget()

	if err := budget.spend(-1); err != nil {
		t.Fatalf("negative counts derive nothing and must not be charged: %v", err)
	}
	if err := budget.spend(maxIterations); err != nil {
		t.Fatalf("the full budget must be spendable: %v", err)
	}
	if err := budget.spend(1); !errors.Is(err, ErrTooManyIterations) {
		t.Fatalf("expected ErrTooManyIterations, got: %v", err)
	}
}
