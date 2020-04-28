package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/colinnewell/pwsafe-de-dup"
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
	s := pwsafe.PWSafeV3{}

	files := os.Args[1:]
	if len(files) == 0 {
		log.Fatal("Must specify filename")
	}

	file, err := os.Open(files[0])
	if err != nil {
		log.Fatal("Error while opening file", err)
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
	fmt.Printf("%#v\n", s)
}
