package main

import (
	"fmt"
	"log"
	"os"

	pwsafe "github.com/colinnewell/pwsafe-de-dup"
)

func main() {
	files := os.Args[1:]
	if len(files) == 0 {
		log.Fatal("Must specify filename")
	}

	file, err := os.Open(files[0])
	if err != nil {
		log.Fatal("Error while opening file", err)
	}

	pwFile, err := pwsafe.Load(file)
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
	uniquePasswords := 0
	for _, v := range uuids {
		fmt.Println(v.String())
		uniquePasswords++
	}
	fmt.Printf("Total passwords %d, unique %d\n", totalPasswords, uniquePasswords)
}
