package pwsafe

import (
	"encoding/binary"
	"fmt"
	"strings"

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

func (p *PasswordRecord) String() string {
	var b strings.Builder
	b.WriteString("PasswordRecord:\n")
	for _, v := range p.Fields {
		b.WriteString(v.String())
		b.WriteString("\n")
	}
	return b.String()
}

func NewPasswordRecord() PasswordRecord {
	return PasswordRecord{Fields: make(map[byte]Field)}
}

func (f *Field) String() string {
	var typename string
	switch f.Type {
	case Autotype:
		typename = "Autotype"
	case CreationTime:
		typename = "CreationTime"
	case CreditCardExpiration:
		typename = "CreditCardExpiration"
	case CreditCardNumber:
		typename = "CreditCardNumber"
	case CreditCardPIN:
		typename = "CreditCardPIN"
	case CreditCardVerifValue:
		typename = "CreditCardVerifValue"
	case DoubleClickAction:
		typename = "DoubleClickAction"
	case EMailAddress:
		typename = "EMailAddress"
	case EntryKeyboardShortcut:
		typename = "EntryKeyboardShortcut"
	case Group:
		typename = "Group"
	case LastAccessTime:
		typename = "LastAccessTime"
	case LastModificationTime:
		typename = "LastModificationTime"
	case Notes:
		typename = "Notes"
	case OwnSymbolsForPassword:
		typename = "OwnSymbolsForPassword"
	case Password:
		typename = "Password"
	case PasswordExpiryInterval:
		typename = "PasswordExpiryInterval"
	case PasswordExpiryTime:
		typename = "PasswordExpiryTime"
	case PasswordHistory:
		typename = "PasswordHistory"
	case PasswordModificationTime:
		typename = "PasswordModificationTime"
	case PasswordPolicy:
		typename = "PasswordPolicy"
	case PasswordPolicyName:
		typename = "PasswordPolicyName"
	case ProtectedEntry:
		typename = "ProtectedEntry"
	case QRCode:
		typename = "QRCode"
	case RunCommand:
		typename = "RunCommand"
	case ShiftDoubleClickAction:
		typename = "ShiftDoubleClickAction"
	case Title:
		typename = "Title"
	case TwoFactorKey:
		typename = "TwoFactorKey"
	case URL:
		typename = "URL"
	case Username:
		typename = "Username"
	case UUID:
		typename = "UUID"
	default:
		typename = fmt.Sprintf("Unknown (%d)", f.Type)
	}
	return fmt.Sprintf("%s: %v", typename, f.Data)
}

func (p *PasswordRecord) AddField(typeID byte, rawData []byte) error {
	var data interface{}
	switch typeID {
	case UUID:
		// uuid
		var err error
		data, err = uuid.FromBytes(rawData)
		if err != nil {
			return err
		}
	case CreationTime, PasswordModificationTime, LastAccessTime,
		PasswordExpiryTime, LastModificationTime:
		// time_t
		data = binary.LittleEndian.Uint32(rawData[:])
	case Group, Autotype, CreditCardExpiration, CreditCardNumber,
		CreditCardPIN, CreditCardVerifValue, EMailAddress, Notes,
		OwnSymbolsForPassword, Password, PasswordHistory, PasswordPolicy,
		PasswordPolicyName, QRCode, RunCommand, Title, URL, Username:
		// string
		data = string(rawData)
	default:
		// there are various types we know about that are
		// binary so we're letting them come here as well
		// as things we're not aware of
		data = rawData
	}

	p.Fields[typeID] = Field{Type: typeID, Data: data}
	return nil
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
