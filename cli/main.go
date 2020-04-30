package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
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
	size := unsafe.Sizeof(s)
	data := make([]byte, size)
	read, err := file.Read(data)
	if err != nil {
		log.Fatal(err)
	}
	if read < int(size) {
		log.Fatal("Failed to read enough of the file")
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
	if subtle.ConstantTimeCompare(hp, s.HP[:]) == 0 {
		log.Fatal("Password incorrect")
	}

	fmt.Println("")

	e, err := twofish.NewCipher(p)
	if err != nil {
		log.Fatal(err)
	}
	e.Decrypt(s.B1B2[0:16], s.B1B2[0:16])
	e.Decrypt(s.B1B2[16:], s.B1B2[16:])

	e.Decrypt(s.B3B4[0:16], s.B3B4[0:16])
	e.Decrypt(s.B3B4[16:], s.B3B4[16:])

	hm := hmac.New(sha256.New, s.B3B4[:])

	k, err := twofish.NewCipher(s.B1B2[:])
	if err != nil {
		log.Fatal(err)
	}

	mode := cipher.NewCBCDecrypter(k, s.IV[:])

	chunk := [16]byte{}
	var headerList []pwsafe.HeaderRecord

	var pwRecord *pwsafe.PasswordRecord
	var passwords []pwsafe.PasswordRecord
	for {
		read, err := file.Read(chunk[:])
		if read < 16 || err != nil {
			break
		}
		if string(chunk[:]) == "PWS3-EOFPWS3-EOF" {
			break
		}
		mode.CryptBlocks(chunk[:], chunk[:])

		record := pwsafe.Record{}
		err = binary.Read(bytes.NewBuffer(chunk[:]), binary.LittleEndian, &record)
		if err != nil {
			log.Fatal(err)
		}

		raw_data := make([]byte, record.Length)
		if record.Length >= 11 {
			needed := record.Length - 11
			copy(raw_data, record.Raw[:])
			start := 11
			for needed > 0 {
				read, err = file.Read(chunk[:])
				if read < 16 || err != nil {
					break
				}
				mode.CryptBlocks(chunk[:], chunk[:])

				if needed > 16 {
					copy(raw_data[start:], chunk[:])
				} else {
					copy(raw_data[start:], chunk[:needed])
				}
				if needed >= 16 {
					needed -= 16
				} else {
					needed = 0
				}
				start += 16
			}
		} else {
			copy(raw_data, record.Raw[:record.Length])
		}
		hm.Write(raw_data)

		if record.Type == 0xff {
			if pwRecord != nil {
				passwords = append(passwords, *pwRecord)
			}
			rec := pwsafe.NewPasswordRecord()
			pwRecord = &rec
			continue
		}
		if pwRecord == nil {
			h, err := pwsafe.NewHeader(record.Type, raw_data)
			if err != nil {
				log.Fatal(err)
			}
			headerList = append(headerList, h)
		} else {
			err := pwRecord.AddField(record.Type, raw_data)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	if err != nil {
		log.Fatal(err)
	}
	var storedHMAC [32]byte
	read, err = file.Read(storedHMAC[:])
	if err != nil {
		log.Fatal(err)
	}
	if read < 32 {
		log.Fatal("Missed hmac")
	}
	actualHMAC := hm.Sum(nil)
	if !hmac.Equal(actualHMAC, storedHMAC[:]) {
		log.Fatal("HMAC doesn't match")
	}

	fmt.Println("=== Headers")
	for _, h := range headerList {
		fmt.Printf("%s\n", h.String())
	}
	fmt.Println("")
	fmt.Println("=== Records")
	uuids := make(map[[32]byte]pwsafe.PasswordRecord)
	totalPasswords := 0
	for _, p := range passwords {
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
