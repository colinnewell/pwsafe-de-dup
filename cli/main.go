package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	pwsafe "github.com/colinnewell/pwsafe-de-dup"
	"golang.org/x/crypto/ssh/terminal"
)

var displayDuplicates bool

func main() {
	flag.BoolVar(&displayDuplicates, "display-duplicates", false, "Display duplicates")
	flag.Parse()

	files := flag.Args()
	if len(files) < 2 {
		log.Fatal("Must specify filename")
	}

	file, err := os.Open(files[0])
	if err != nil {
		log.Fatal("Error while opening file", err)
	}
	defer file.Close()

	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}

	pwFile, err := pwsafe.Load(file, bytePassword)
	if err != nil {
		log.Fatal(err)
	}

	uuids := make(map[[32]byte]pwsafe.PasswordRecord)
	totalPasswords := 0
	for _, p := range pwFile.Passwords {
		if displayDuplicates {
			_, ok := uuids[p.Sha256()]
			if ok {
				fmt.Println(p.String())
				o := uuids[p.Sha256()]
				fmt.Println(o.String())
			}
		}
		uuids[p.Sha256()] = p
		totalPasswords++
	}
	var uniquePasswords []pwsafe.PasswordRecord
	for _, v := range uuids {
		uniquePasswords = append(uniquePasswords, v)
	}
	fmt.Printf("Total passwords %d, unique %d\n", totalPasswords, len(uniquePasswords))
	pwFile.Passwords = uniquePasswords

	op, err := os.Create(files[1])
	defer op.Close()
	if err != nil {
		log.Fatal(err)
	}

	if err := pwFile.Write(op, bytePassword); err != nil {
		log.Fatal(err)
	}
}
