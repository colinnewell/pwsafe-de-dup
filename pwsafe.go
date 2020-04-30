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
)

type HeaderRecord struct {
	Type byte
	Data interface{}
}

func NewHeader(typeID byte, raw_data []byte) (HeaderRecord, error) {
	var data interface{}
	switch typeID {
	case Version:
		// 2 bytes, major/minor
		data = fmt.Sprintf("%d.%d", raw_data[1], raw_data[0])
	case UUID:
		// uuid
		var err error
		fmt.Printf("%#v\n", raw_data)
		data, err = uuid.FromBytes(raw_data)
		if err != nil {
			return HeaderRecord{}, err
		}
	case TimestampOfLastSave, LastMasterPasswordChange:
		// time_t
		data = binary.LittleEndian.Uint32(raw_data[:])
	case DatabaseDescription, DatabaseFilters, DatabaseName, EmptyGroups,
		EndOfEntry, LastSavedByUser, LastSavedOnHost, NamedPasswordPolicies,
		NondefaultPreferences, RecentlyUsedEntries, TreeDisplayStatus,
		WhatPerformedLastSave, WhoPerformedLastSave, Yubico:
		// string
		data = string(raw_data)
	default:
		data = raw_data
	}
	return HeaderRecord{Type: typeID, Data: data}, nil
}
