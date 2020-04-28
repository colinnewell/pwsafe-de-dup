package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"github.com/colinnewell/pwsafe-de-dup"
	"golang.org/x/crypto/ssh/terminal"
)

func readNextBytes(file *os.File, number int) ([]byte, error) {
	bytes := make([]byte, number)

	_, err := file.Read(bytes)
	if err != nil {
		return bytes, err
	}

	return bytes, nil
}

func main() {
	fmt.Println("vim-go")
	s := pwsafe.HeaderV3{}

	files := os.Args[1:]
	if len(files) == 0 {
		log.Fatal("Must specify filename")
	}

	file, err := os.Open(files[0])
	if err != nil {
		log.Fatal("Error while opening file", err)
	}

	info, err := file.Stat()
	if err != nil {
		log.Fatal(err)
	}
	if info.Size() < 232 {
		log.Fatal("File truncated")
	}

	defer file.Close()
	data, err := readNextBytes(file, int(unsafe.Sizeof(s)))
	if err != nil {
		log.Fatal(err)
	}

	buffer := bytes.NewBuffer(data)

	if err := binary.Read(buffer, binary.LittleEndian, &s); err != nil {
		log.Fatal(err)
	}
	if string(s.Tag[:]) != "PWS3" {
		log.Fatal("Header tag missing")
	}

	if s.ITER < 2048 {
		log.Fatal("Iterations too small")
	}

	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.New()
	h.Write(bytePassword)
	h.Write(s.Salt[:])
	hp := h.Sum(nil)
	for i := uint32(0); i <= s.ITER; i++ {
		h = sha256.New()
		h.Write(hp)
		hp = h.Sum(nil)
	}
	if bytes.Compare(hp, s.HP[:]) != 0 {
		log.Fatal("Password incorrect")
	}

	fmt.Println("")
	fmt.Println("Password OK")
}
