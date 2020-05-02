// +build gofuzz

package pwsafe

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-cmp/cmp"
	fuzz "github.com/google/gofuzz"
	"github.com/google/uuid"
)

func Fuzz(data []byte) int {
	var pwFile V3File
	f := fuzz.NewFromGoFuzz(data).Funcs(
		func(h *HeaderRecord, c fuzz.Continue) {
			var typeID byte
			c.Fuzz(&typeID)
			*h = HeaderRecord{Type: typeID}
			switch typeID {
			case Version:
				h.Data = "3.0" // FIXME:!
			case UUID:
				// uuid
				var u uuid.UUID
				c.Fuzz(&u)
				h.Data = u
			case TimestampOfLastSave, LastMasterPasswordChange:
				// time_t
				var t uint32
				c.Fuzz(&t)
				h.Data = t
			case DatabaseDescription, DatabaseFilters, DatabaseName, EmptyGroups,
				EndOfEntry, LastSavedByUser, LastSavedOnHost, NamedPasswordPolicies,
				NondefaultPreferences, RecentlyUsedEntries, TreeDisplayStatus,
				WhatPerformedLastSave, WhoPerformedLastSave, Yubico:
				// string
				var val string
				c.Fuzz(&val)
				(*h).Data = val
			default:
				var bytes []byte
				c.Fuzz(&bytes)
				h.Data = bytes
			}
		},
		func(r *Field, c fuzz.Continue) {
			var typeID byte
			c.Fuzz(&typeID)
			*r = Field{Type: typeID}
			switch typeID {
			case UUID:
				// uuid
				var u uuid.UUID
				c.Fuzz(&u)
				r.Data = u
			case CreationTime, PasswordModificationTime,
				LastAccessTime, PasswordExpiryTime,
				LastModificationTime:
				// time_t
				var t uint32
				c.Fuzz(&t)
				r.Data = t
			case Group, Autotype, CreditCardExpiration,
				CreditCardNumber, CreditCardPIN,
				CreditCardVerifValue, EMailAddress, Notes,
				OwnSymbolsForPassword, Password, PasswordHistory,
				PasswordPolicy, PasswordPolicyName, QRCode,
				RunCommand, Title, URL, Username:
				// string
				var val string
				c.Fuzz(&val)
				r.Data = val
			default:
				// there are various types we know about that are
				// binary so we're letting them come here as well
				// as things we're not aware of
				var bytes []byte
				c.Fuzz(&bytes)
				r.Data = bytes
			}
		},
		func(r *PasswordRecord, c fuzz.Continue) {
			// FIXME: need to do a loop and create fields
			// need to do some mandatory fields + some random
			var password string
			var user string
			var u uuid.UUID
			c.Fuzz(&password)
			c.Fuzz(&user)
			c.Fuzz(&u)
			*r = PasswordRecord{
				Fields: map[byte]Field{
					UUID: Field{
						Type: UUID,
						Data: u,
					},
					Username: Field{
						Type: Username,
						Data: user,
					},
					Password: Field{
						Type: Password,
						Data: password,
					},
				},
			}
			var extra_fields []Field
			c.Fuzz(&extra_fields)
			// now poplate the fields
			for i := range extra_fields {
				r.Fields[extra_fields[i].Type] = extra_fields[i]
			}

		},
	)
	f.Fuzz(&pwFile)
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
