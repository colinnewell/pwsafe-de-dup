package pwsafe_test

import (
	"io/ioutil"
	"os"
	"testing"

	pwsafe "github.com/colinnewell/pwsafe-de-dup"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestRoundTrip(t *testing.T) {
	zeros := [16]byte{}
	blank_uuid, err := uuid.FromBytes(zeros[:])
	if err != nil {
		t.Error(err)
	}
	pwFile := pwsafe.V3File{
		Headers: []pwsafe.HeaderRecord{
			pwsafe.HeaderRecord{
				Type: pwsafe.UUID,
				Data: blank_uuid,
			},
		},
		Passwords: []pwsafe.PasswordRecord{
			pwsafe.PasswordRecord{
				Fields: map[byte]pwsafe.Field{
					pwsafe.UUID: pwsafe.Field{
						Type: pwsafe.UUID,
						Data: uuid.New(),
					},
				},
			},
		},
	}

	op, err := ioutil.TempFile("", "psafe3-test")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(op.Name())

	password := []byte("test password")
	if err := pwFile.Write(op, password); err != nil {
		t.Error(err)
	}
	if err := op.Close(); err != nil {
		t.Error(err)
	}

	// then read back in.
	file, err := os.Open(op.Name())
	if err != nil {
		t.Error(err)
	}
	defer file.Close()

	readFile, err := pwsafe.Load(file, password)
	if err != nil {
		t.Error(err)
	}

	// then compare
	if diff := cmp.Diff(pwFile, readFile); diff != "" {
		t.Errorf("Round trip not identical (-wrote +read):\n%s\n", diff)
	}
}
