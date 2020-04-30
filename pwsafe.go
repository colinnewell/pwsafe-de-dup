package pwsafe

import (
	"encoding/binary"
	"fmt"

	"github.com/google/uuid"
)

// HeaderV3 Password Safe V3 header
// min size 232
// check for PWS3
// should have EOF block PWS3-EOF
type HeaderV3 struct {
	Tag  [4]byte
	Salt [32]byte
	ITER uint32 // should be > 2048
	HP   [32]byte
	B1B2 [32]byte
	B3B4 [32]byte

	IV [16]byte
	// https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt
}

type Record struct {
	Length uint32
	Type   byte
	Raw    [11]byte
}

const (
	// header types
	DatabaseDescription      = 0x0a
	DatabaseFilters          = 0x0b
	DatabaseName             = 0x09
	EmptyGroups              = 0x11
	EndOfEntry               = 0xff
	LastMasterPasswordChange = 0x13
	LastSavedByUser          = 0x07
	LastSavedOnHost          = 0x08
	NamedPasswordPolicies    = 0x10
	NondefaultPreferences    = 0x02
	RecentlyUsedEntries      = 0x0f
	TimestampOfLastSave      = 0x04
	TreeDisplayStatus        = 0x03
	UUID                     = 0x01
	Version                  = 0x00
	WhatPerformedLastSave    = 0x06
	WhoPerformedLastSave     = 0x05
	Yubico                   = 0x12

	// record types
	Autotype                 = 0x0e
	CreationTime             = 0x07
	CreditCardExpiration     = 0x1d
	CreditCardNumber         = 0x1c
	CreditCardPIN            = 0x1f
	CreditCardVerifValue     = 0x1e
	DoubleClickAction        = 0x13
	EMailAddress             = 0x14
	EntryKeyboardShortcut    = 0x19
	Group                    = 0x02
	LastAccessTime           = 0x09
	LastModificationTime     = 0x0c
	Notes                    = 0x05
	OwnSymbolsForPassword    = 0x16
	Password                 = 0x06
	PasswordExpiryInterval   = 0x11
	PasswordExpiryTime       = 0x0a
	PasswordHistory          = 0x0f
	PasswordModificationTime = 0x08
	PasswordPolicy           = 0x10
	PasswordPolicyName       = 0x18
	ProtectedEntry           = 0x15
	QRCode                   = 0x20
	RunCommand               = 0x12
	ShiftDoubleClickAction   = 0x17
	Title                    = 0x03
	TwoFactorKey             = 0x1b
	URL                      = 0x0d
	Username                 = 0x04
)

type HeaderRecord struct {
	Type byte
	Data interface{}
}

type PasswordRecord struct {
	// this makes the assumption that you can only have one field of each type.
	Fields map[byte]Field
}

type Field struct {
	Type byte
	Data interface{}
}

func (h *HeaderRecord) String() string {
	var typename string
	switch h.Type {
	case DatabaseDescription:
		typename = "DatabaseDescription"
	case DatabaseFilters:
		typename = "DatabaseFilters"
	case DatabaseName:
		typename = "DatabaseName"
	case EmptyGroups:
		typename = "EmptyGroups"
	case EndOfEntry:
		typename = "EndOfEntry"
	case LastMasterPasswordChange:
		typename = "LastMasterPasswordChange"
	case LastSavedByUser:
		typename = "LastSavedByUser"
	case LastSavedOnHost:
		typename = "LastSavedOnHost"
	case NamedPasswordPolicies:
		typename = "NamedPasswordPolicies"
	case NondefaultPreferences:
		typename = "NondefaultPreferences"
	case RecentlyUsedEntries:
		typename = "RecentlyUsedEntries"
	case TimestampOfLastSave:
		typename = "TimestampOfLastSave"
	case TreeDisplayStatus:
		typename = "TreeDisplayStatus"
	case UUID:
		typename = "UUID"
	case Version:
		typename = "Version"
	case WhatPerformedLastSave:
		typename = "WhatPerformedLastSave"
	case WhoPerformedLastSave:
		typename = "WhoPerformedLastSave"
	case Yubico:
		typename = "Yubico"
	default:
		typename = fmt.Sprintf("Unknown (%d)", h.Type)
	}
	return fmt.Sprintf("%s: %v", typename, h.Data)
}

func NewHeader(typeID byte, rawData []byte) (HeaderRecord, error) {
	var data interface{}
	switch typeID {
	case Version:
		// 2 bytes, major/minor
		data = fmt.Sprintf("%d.%d", rawData[1], rawData[0])
	case UUID:
		// uuid
		var err error
		data, err = uuid.FromBytes(rawData)
		if err != nil {
			return HeaderRecord{}, err
		}
	case TimestampOfLastSave, LastMasterPasswordChange:
		// time_t
		data = binary.LittleEndian.Uint32(rawData[:])
	case DatabaseDescription, DatabaseFilters, DatabaseName, EmptyGroups,
		EndOfEntry, LastSavedByUser, LastSavedOnHost, NamedPasswordPolicies,
		NondefaultPreferences, RecentlyUsedEntries, TreeDisplayStatus,
		WhatPerformedLastSave, WhoPerformedLastSave, Yubico:
		// string
		data = string(rawData)
	default:
		data = rawData
	}
	return HeaderRecord{Type: typeID, Data: data}, nil
}
