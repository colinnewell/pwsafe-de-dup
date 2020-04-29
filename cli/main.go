package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	pwsafe "github.com/colinnewell/pwsafe-de-dup"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/crypto/twofish"
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
	p := h.Sum(nil)
	for i := uint32(0); i < s.ITER; i++ {
		h = sha256.New()
		h.Write(p)
		p = h.Sum(nil)
	}
	h = sha256.New()
	h.Write(p)
	hp := h.Sum(nil)
	if bytes.Compare(hp, s.HP[:]) != 0 {
		log.Fatal("Password incorrect")
	}

	fmt.Println("")
	fmt.Println("Password OK")

	e, err := twofish.NewCipher(p)
	if err != nil {
		log.Fatal(err)
	}
	e.Decrypt(s.B1B2[0:16], s.B1B2[0:16])
	e.Decrypt(s.B1B2[16:], s.B1B2[16:])

	e.Decrypt(s.B3B4[0:16], s.B3B4[0:16])
	e.Decrypt(s.B3B4[16:], s.B3B4[16:])

	if string(s.Header[:]) == "PWS3-EOFPWS3-EOF" {
		return
	}
	hm := hmac.New(sha256.New, s.B3B4[:])

	k, err := twofish.NewCipher(s.B1B2[:])

	mode := cipher.NewCBCDecrypter(k, s.IV[:])
	var header [16]byte
	mode.CryptBlocks(header[:], s.Header[:])

	record := pwsafe.Record{}
	binary.Read(bytes.NewBuffer(header[0:5]), binary.LittleEndian, &record)
	// start with headers until we hit the 0xff
	// then onto regular records
	// now read the records
	// then we get to a
}
