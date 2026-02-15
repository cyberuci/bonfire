package main

import (
	"atoll"
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"golang.org/x/term"
	"log"
	"os"
	"regexp"
	"strconv"
	"syscall"
	"unicode"
)

var HELP = `
Password Generator: 
Modified version of atoll
Written by Payton Erickson

-csv [str]  The name of the csv file that will be outputted (default: passwords.db)
`

func PassphraseGen(p *atoll.Passphrase) [][]byte {
	passphrase, err := atoll.NewSecret(p)
	if err != nil {
		log.Fatal(err)
	}

	return passphrase
}

func PasswordGen(p *atoll.Password) [][]byte {
	password, err := atoll.NewSecret(p)
	if err != nil {
		log.Fatal(err)
	}

	return password
}

func WordListGen(path string) [][]byte {
	wordlist := [][]byte{}

	// open file
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	// remember to close the file at the end of the program
	defer f.Close()

	// read the file word by word using scanner
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanWords)

	// some diceware wordlists have info before the list, but every list starts with some form of 11 before the words
	wl_indexed := false
	r, _ := regexp.Compile("1[-|1]")

	for scanner.Scan() {
		// if we are at the word part of the list start adding them to the array
		if wl_indexed {
			if CheckWord(scanner.Text()) {
				wordlist = append(wordlist, []byte(scanner.Text()))
			}
		} else {
			// check if we made it to the 11 part yet
			if r.MatchString(scanner.Text()) {
				wl_indexed = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return wordlist
}

func CheckWord(word string) bool {
	valid_word := true
	for i := 0; i < len(word); i++ {
		if !unicode.IsLetter(int32(word[i])) && word[i] != '-' {
			valid_word = false
			fmt.Println("INVALID WORD: ", word)
			break
		}
	}
	return valid_word
}

func CsvOutput(name string, pass_list [][]byte) {
	// Write the CSV data
	file2, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer file2.Close()

	writer := csv.NewWriter(file2)
	defer writer.Flush()
	// this defines the header value and data values for the new csv file
	headers := []string{"id", "password"}

	writer.Write(headers)
	for i := 0; i < len(pass_list); i++ {
		writer.Write([]string{strconv.Itoa(i), string(pass_list[i])})
	}
}

func main() {
	/*
		--------------------------------------------------------------------------------------------------------------
															ARGS
		--------------------------------------------------------------------------------------------------------------
	*/
	argsWithoutProg := os.Args[1:]
	//Letter/word count
	count := uint64(3)
	//output file name
	batch_count := uint64(90)
	//separator character
	separator := "-"
	//wordlist txt file that holds all words used to generate passphrases
	wordlist_path := ""
	//atoll word list to use
	wordlist_type := atoll.WordListNumCap
	wlt := "wlnc"
	//password levels
	//csv file
	csv_name := "passwords.db"
	//Seed for random number generation (after sha256 hashing)
	seed := [32]byte{}

	for i := 0; i < len(argsWithoutProg); i++ {
		switch argsWithoutProg[i] {
		case "-h":
			fmt.Println(HELP)
			os.Exit(0)
		case "-csv":
			i++
			csv_name = argsWithoutProg[i]
		}
	}
	/*
		--------------------------------------------------------------------------------------------------------------
												Print ARGS + Get SEED
		--------------------------------------------------------------------------------------------------------------
	*/
	fmt.Printf("CSV File Name: %v\n", csv_name)

	fmt.Println("Enter Seed or Enter to continue")
	temp, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		os.Exit(1)
	}
	if temp != nil {
		seed = sha256.Sum256(temp)
		temp = nil
	}

	/*
		--------------------------------------------------------------------------------------------------------------
												PASSWORD / PASSPHRASE
		--------------------------------------------------------------------------------------------------------------
	*/

	// Setup Passphrases
	p := &atoll.Passphrase{
		Length:    count,
		Separator: separator,
		Number:    batch_count,
		Seed:      seed,
	}

	// Get wordlist if arg is passed
	if wordlist_path != "" {
		p.WordList = WordListGen(wordlist_path)
		// Get the wordlist type if arg is passed
		if wlt != "nl" {
			p.List = wordlist_type
		} else {
			p.List = atoll.WordList
		}
	} else {
		p.List = wordlist_type
	}

	// Make an array of byte strings that is as large as the number of passphrases generated
	pass_list := make([][]byte, batch_count)
	//Generate passwords
	pass_list = PassphraseGen(p)

	// Output to csv if arg is passed in
	if csv_name != "" {
		CsvOutput(csv_name, pass_list)
	} else {
		fmt.Println("Password(s):")
		for i := 0; i < int(batch_count); i++ {
			fmt.Println(string(pass_list[i]))
		}
	}
}
