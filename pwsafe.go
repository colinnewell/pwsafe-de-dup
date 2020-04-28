package pwsafe

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

	IV     [16]byte
	Header [16]byte
	// https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt
}

type Record struct {
	Length uint32
	Type   byte
	Raw    []byte
}
