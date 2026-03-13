package core

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
)

type PasswordEntry struct {
	ID       int
	Password string
}

func LoadPasswords(path string) ([]PasswordEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %w", err)
	}

	var passwords []PasswordEntry

	startRow := 0
	if len(records) > 0 && records[0][0] == "id" {
		startRow = 1
	}

	for i := startRow; i < len(records); i++ {
		row := records[i]
		if len(row) < 2 {
			continue
		}
		id, err := strconv.Atoi(row[0])
		if err != nil {
			continue
		}
		passwords = append(passwords, PasswordEntry{
			ID:       id,
			Password: row[1],
		})
	}

	return passwords, nil
}

func SavePasswords(path string, passwords []PasswordEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	if err := writer.Write([]string{"id", "password"}); err != nil {
		return err
	}

	for _, p := range passwords {
		if err := writer.Write([]string{strconv.Itoa(p.ID), p.Password}); err != nil {
			return err
		}
	}

	return nil
}
