package main

import (
	"fmt"
	"log"
	"os"
	"syscall"

	pwsafe "github.com/colinnewell/pwsafe-de-dup"
	"github.com/google/uuid"
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

	byHash := make(map[[32]byte]pwsafe.PasswordRecord)
	totalPasswords := 0
	for _, p := range pwFile.Passwords {
		byHash[p.Sha256()] = p
		totalPasswords++
	}
	var uniquePasswords []pwsafe.PasswordRecord
	for _, v := range byHash {
		uniquePasswords = append(uniquePasswords, v)
	}
	// now fix up uuids so that they are unique to prevent
	// clash detection losing the plot in future.
	byUUID := make(map[uuid.UUID]bool)
	fixedUUIDs := 0
	for _, v := range uniquePasswords {
		u := v.Fields[pwsafe.UUID]
		_, ok := byUUID[u.Data.(uuid.UUID)]
		changed := false
		for ok {
			changed = true
			u.Data = uuid.New()
			_, ok = byUUID[u.Data.(uuid.UUID)]
		}
		if changed {
			fixedUUIDs++
		}
		byUUID[u.Data.(uuid.UUID)] = true
	}

	fmt.Printf("Total passwords %d, unique %d, duplicate uuid's fixed up: %d\n", totalPasswords, len(uniquePasswords), fixedUUIDs)
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
