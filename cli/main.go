package main

import (
	"fmt"
	"log"
	"os"
	"syscall"

	pwsafe "github.com/colinnewell/pwsafe-de-dup"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	files := os.Args[1:]
	if len(files) < 2 {
		log.Fatal("Must specify filename")
	}

	file, err := os.Open(files[0])
	if err != nil {
		log.Fatal("Error while opening file", err)
	}

	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}

	pwFile, err := pwsafe.Load(file, bytePassword)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("=== Headers")
	for _, h := range pwFile.Headers {
		fmt.Printf("%s\n", h.String())
	}
	fmt.Println("")
	fmt.Println("=== Records")
	uuids := make(map[[32]byte]pwsafe.PasswordRecord)
	totalPasswords := 0
	for _, p := range pwFile.Passwords {
		uuids[p.Sha256()] = p
		totalPasswords++
	}
	var uniquePasswords []pwsafe.PasswordRecord
	for _, v := range uuids {
		fmt.Println(v.String())
		uniquePasswords = append(uniquePasswords, v)
	}
	fmt.Printf("Total passwords %d, unique %d\n", totalPasswords, len(uniquePasswords))
	pwFile.Passwords = uniquePasswords

	op, err := os.Create(files[1])
	if err != nil {
		log.Fatal(err)
	}

	if err := pwFile.Write(op, bytePassword); err != nil {
		log.Fatal(err)
	}
}
