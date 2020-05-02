// +build gofuzz

package pwsafe

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-cmp/cmp"
	fuzz "github.com/google/gofuzz"
)

func Fuzz(data []byte) int {
	var pwFile V3File
	fuzz.NewFromGoFuzz(data).Fuzz(&pwFile)
	TestRoundTrip(pwFile)

	return 0
}

func TestRoundTrip(pwFile V3File) {
	op, err := ioutil.TempFile("", "psafe3-test")
	if err != nil {
		panic(err)
	}
	defer os.Remove(op.Name())

	password := []byte("test password")
	if err := pwFile.Write(op, password); err != nil {
		panic(err)
	}
	if err := op.Close(); err != nil {
		panic(err)
	}

	// then read back in.
	file, err := os.Open(op.Name())
	if err != nil {
		panic(err)
	}
	defer file.Close()

	readFile, err := Load(file, password)
	if err != nil {
		panic(err)
	}

	// then compare
	if diff := cmp.Diff(pwFile, readFile); diff != "" {
		panic(fmt.Errorf("Round trip not identical (-wrote +read):\n%s\n", diff))
	}
}
