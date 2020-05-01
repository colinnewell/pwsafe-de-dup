package pwsafe

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"os"
	"strings"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/crypto/twofish"
)

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

type V3File struct {
	Headers   []HeaderRecord
	Passwords []PasswordRecord
}

type HeaderRecord struct {
	Type byte
	Data interface{}
}

type Field struct {
	Type byte
	Data interface{}
}

type PasswordRecord struct {
	// this makes the assumption that you can only have one field of each type.
	Fields map[byte]Field
}

type fileHeader struct {
	Tag  [4]byte
	Salt [32]byte
	ITER uint32
	HP   [32]byte
	B1B2 [32]byte
	B3B4 [32]byte

	IV [16]byte
	// https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt
}

type recordHeader struct {
	Length uint32
	Type   byte
	Raw    [11]byte
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

func (p *PasswordRecord) Sha256() [32]byte {
	h := sha256.New()
	for _, v := range p.Fields {
		h.Write([]byte(v.String()))
	}
	var sha [32]byte
	r := h.Sum(nil)
	copy(sha[:], r)
	return sha
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

func Load(file *os.File, password []byte) (V3File, error) {
	info, err := file.Stat()
	if err != nil {
		return V3File{}, err
	}
	if info.Size() < 232 {
		return V3File{}, fmt.Errorf("File truncated")
	}

	defer file.Close()

	s := fileHeader{}
	size := unsafe.Sizeof(s)
	data := make([]byte, size)
	read, err := file.Read(data)
	if err != nil {
		return V3File{}, err
	}
	if read < int(size) {
		return V3File{}, fmt.Errorf("Failed to read enough of the file")
	}

	buffer := bytes.NewBuffer(data)

	if err := binary.Read(buffer, binary.LittleEndian, &s); err != nil {
		return V3File{}, err
	}
	if string(s.Tag[:]) != "PWS3" {
		return V3File{}, fmt.Errorf("Header tag missing")
	}

	if s.ITER < 2048 {
		return V3File{}, fmt.Errorf("Iterations too small")
	}

	h := sha256.New()
	h.Write(password)
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
		return V3File{}, fmt.Errorf("Password incorrect")
	}

	fmt.Println("")

	e, err := twofish.NewCipher(p)
	if err != nil {
		return V3File{}, err
	}
	e.Decrypt(s.B1B2[0:16], s.B1B2[0:16])
	e.Decrypt(s.B1B2[16:], s.B1B2[16:])

	e.Decrypt(s.B3B4[0:16], s.B3B4[0:16])
	e.Decrypt(s.B3B4[16:], s.B3B4[16:])

	hm := hmac.New(sha256.New, s.B3B4[:])

	k, err := twofish.NewCipher(s.B1B2[:])
	if err != nil {
		return V3File{}, err
	}

	mode := cipher.NewCBCDecrypter(k, s.IV[:])

	chunk := [16]byte{}
	var headerList []HeaderRecord

	var pwRecord *PasswordRecord
	var passwords []PasswordRecord
	for {
		read, err := file.Read(chunk[:])
		if read < 16 || err != nil {
			break
		}
		if string(chunk[:]) == "PWS3-EOFPWS3-EOF" {
			break
		}
		mode.CryptBlocks(chunk[:], chunk[:])

		record := recordHeader{}
		err = binary.Read(bytes.NewBuffer(chunk[:]), binary.LittleEndian, &record)
		if err != nil {
			return V3File{}, err
		}

		// FIXME: not sure what the ideal sanity check here is.
		if record.Length > 1000 {
			return V3File{}, fmt.Errorf("Record length %d seems too large", record.Length)
		}
		rawData := make([]byte, record.Length)
		if record.Length >= 11 {
			needed := record.Length - 11
			copy(rawData, record.Raw[:])
			start := 11
			for needed > 0 {
				read, err = file.Read(chunk[:])
				if read < 16 || err != nil {
					break
				}
				mode.CryptBlocks(chunk[:], chunk[:])

				if needed > 16 {
					copy(rawData[start:], chunk[:])
				} else {
					copy(rawData[start:], chunk[:needed])
				}
				if needed >= 16 {
					needed -= 16
				} else {
					needed = 0
				}
				start += 16
			}
		} else {
			copy(rawData, record.Raw[:record.Length])
		}
		hm.Write(rawData)

		if record.Type == 0xff {
			if pwRecord != nil {
				passwords = append(passwords, *pwRecord)
			}
			rec := NewPasswordRecord()
			pwRecord = &rec
			continue
		}
		if pwRecord == nil {
			h, err := NewHeader(record.Type, rawData)
			if err != nil {
				return V3File{}, err
			}
			headerList = append(headerList, h)
		} else {
			err := pwRecord.AddField(record.Type, rawData)
			if err != nil {
				return V3File{}, err
			}
		}
	}
	if err != nil {
		return V3File{}, err
	}
	var storedHMAC [32]byte
	read, err = file.Read(storedHMAC[:])
	if err != nil {
		return V3File{}, err
	}
	if read < 32 {
		return V3File{}, fmt.Errorf("Missed hmac")
	}
	actualHMAC := hm.Sum(nil)
	if !hmac.Equal(actualHMAC, storedHMAC[:]) {
		return V3File{}, fmt.Errorf("HMAC doesn't match")
	}

	return V3File{Headers: headerList, Passwords: passwords}, nil
}

func (v3 *V3File) Write(file *os.File, password []byte) error {
	s := fileHeader{}
	size := unsafe.Sizeof(s)
	randomData := make([]byte, size)
	read, err := rand.Read(randomData)
	if err != nil {
		return err
	}
	if read < int(size) {
		return fmt.Errorf("Failed to read enough random data")
	}

	buffer := bytes.NewBuffer(randomData)
	if err := binary.Read(buffer, binary.LittleEndian, &s); err != nil {
		return err
	}

	s.ITER = 2048
	copy(s.Tag[:], []byte("PWS3"))

	h := sha256.New()
	h.Write(password)
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
	copy(s.HP[:], hp)

	hm := hmac.New(sha256.New, s.B3B4[:])

	k, err := twofish.NewCipher(s.B1B2[:])
	if err != nil {
		return err
	}
	mode := cipher.NewCBCEncrypter(k, s.IV[:])

	// now we've setup the keys encrypt them before we store them.
	e, err := twofish.NewCipher(p)
	if err != nil {
		return err
	}
	e.Encrypt(s.B1B2[0:16], s.B1B2[0:16])
	e.Encrypt(s.B1B2[16:], s.B1B2[16:])

	e.Encrypt(s.B3B4[0:16], s.B3B4[0:16])
	e.Encrypt(s.B3B4[16:], s.B3B4[16:])

	opBuffer := new(bytes.Buffer)
	binary.Write(opBuffer, binary.LittleEndian, s)
	file.Write(opBuffer.Bytes())

	// that's the header done, now write the headers
	for _, header := range v3.Headers {
		block := constructFieldData(header.Type, header.Data, hm)
		mode.CryptBlocks(block, block)
		_, err = file.Write(block)
		if err != nil {
			return err
		}
	}
	block := constructFieldData(EndOfEntry, []byte{}, hm)
	mode.CryptBlocks(block, block)
	_, err = file.Write(block)
	if err != nil {
		return err
	}

	// then write the password records
	for _, record := range v3.Passwords {
		for _, value := range record.Fields {
			block := constructFieldData(value.Type, value.Data, hm)
			mode.CryptBlocks(block, block)
			_, err = file.Write(block)
			if err != nil {
				return err
			}
		}
		block := constructFieldData(EndOfEntry, []byte{}, hm)
		mode.CryptBlocks(block, block)
		_, err = file.Write(block)
		if err != nil {
			return err
		}
	}

	// then write the footer, the plain text EOF + hmac
	_, err = file.Write([]byte("PWS3-EOFPWS3-EOF"))
	if err != nil {
		return err
	}

	_, err = file.Write(hm.Sum(nil))
	if err != nil {
		return err
	}

	return nil
}

func constructFieldData(typeID byte, data interface{}, hm hash.Hash) []byte {
	// construct byte block with sufficient capacity
	var dataInBytes []byte
	if typeID == Version {
		// read this back to 2 bytes
		dataInBytes = make([]byte, 2)
		// FIXME: need to do this properly
		// parse string value back to bytes
		dataInBytes[1] = 3
		dataInBytes[0] = 0
	} else if typeID == EndOfEntry {
		dataInBytes = make([]byte, 0)
	} else {
		switch v := data.(type) {
		case []byte:
			dataInBytes = v
		case string:
			dataInBytes = []byte(v)
		case uint32:
			dataInBytes = make([]byte, 4)
			binary.LittleEndian.PutUint32(dataInBytes[:], v)
		case uuid.UUID:
			dataInBytes, _ = v.MarshalBinary()
		default:
			panic(fmt.Errorf("Unexpected data type %T to convert", data))
		}
	}

	hm.Write(dataInBytes)
	sizeNeeded := 5 + len(dataInBytes)
	blocks := make([]byte, 16*(((sizeNeeded-1)/16)+1))
	if sizeNeeded < len(blocks) {
		// fill the remainder of the block with random bytes
		rand.Read(blocks[sizeNeeded:])
	}
	// populate length and type
	blocks[4] = typeID
	binary.LittleEndian.PutUint32(blocks, uint32(len(dataInBytes)))
	copy(blocks[5:], dataInBytes)
	return blocks
}
