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
	if subtle.ConstantTimeCompare(hp, s.HP[:]) == 0 {
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

	hm := hmac.New(sha256.New, s.B3B4[:])

	k, err := twofish.NewCipher(s.B1B2[:])
	if err != nil {
		log.Fatal(err)
	}

	mode := cipher.NewCBCDecrypter(k, s.IV[:])

	chunk := [16]byte{}
	var headerList []pwsafe.HeaderRecord
	dump, err := os.Create("unencrypted.dump")
	if err != nil {
		log.Fatal(err)
	}
	defer dump.Close()

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

		// FIXME: remove
		_, err = dump.Write(chunk[:])
		if err != nil {
			log.Fatal(err)
		}
		////

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

				// FIXME: remove
				_, err = dump.Write(chunk[:])
				if err != nil {
					log.Fatal(err)
				}
				////

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
		hm.Sum(raw_data)

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
			fmt.Printf("Header %s\n", h.String())
			headerList = append(headerList, h)
		} else {
			err := pwRecord.AddField(record.Type, raw_data)
			if err != nil {
				log.Fatal(err)
			}
			//fmt.Printf("%d: %d: %#v\n", record.Length, record.Type, raw_data)
		}
	}
	for _, p := range passwords {
		fmt.Println(p.String())
	}
	if err != nil {
		// probably check for EoF
		log.Fatal(err)
	}

	// FIXME: grab the hmac from the end of the file and compare with hm
}
