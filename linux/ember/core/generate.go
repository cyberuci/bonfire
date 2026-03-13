package core

import (
	"crypto/sha256"
	"fmt"

	"bonfire/ember/atoll"
)

func GeneratePasswords(seedInput []byte, count uint64) ([]PasswordEntry, error) {

	seed := sha256.Sum256(seedInput)

	wordCount := uint64(3)

	separator := "-"

	p := &atoll.Passphrase{
		Length:    wordCount,
		Separator: separator,
		Number:    count,
		Seed:      seed,
		List:      atoll.WordListNumCap,
	}

	secret, err := atoll.NewSecret(p)
	if err != nil {
		return nil, fmt.Errorf("failed to generate passwords: %w", err)
	}

	entries := make([]PasswordEntry, count)
	for i, s := range secret {
		entries[i] = PasswordEntry{
			ID:       i,
			Password: string(s),
		}
	}

	return entries, nil
}
