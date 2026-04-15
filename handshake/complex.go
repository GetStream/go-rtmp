//
// Copyright (c) 2018- yutopp (yutopp@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at  https://www.boost.org/LICENSE_1_0.txt)
//

package handshake

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// fpKey is the Adobe Flash Player identity key (62 bytes).
// Used as the HMAC key when validating a C1 digest sent by the client.
var fpKey = []byte{
	// "Genuine Adobe Flash Player 001" (30 bytes)
	'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ',
	'A', 'd', 'o', 'b', 'e', ' ', 'F', 'l',
	'a', 's', 'h', ' ', 'P', 'l', 'a', 'y',
	'e', 'r', ' ', '0', '0', '1',
	// suffix (32 bytes)
	0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8,
	0x2E, 0x00, 0xD0, 0xD1, 0x02, 0x9E, 0x7E, 0x57,
	0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
	0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE,
}

// fmsKey is the Flash Media Server identity key (68 bytes).
// Used as the HMAC key when signing S1 and deriving S2.
var fmsKey = []byte{
	// "Genuine Adobe Flash Media Server 001" (36 bytes)
	'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ',
	'A', 'd', 'o', 'b', 'e', ' ', 'F', 'l',
	'a', 's', 'h', ' ', 'M', 'e', 'd', 'i',
	'a', ' ', 'S', 'e', 'r', 'v', 'e', 'r',
	' ', '0', '0', '1',
	// suffix (32 bytes)
	0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8,
	0x2E, 0x00, 0xD0, 0xD1, 0x02, 0x9E, 0x7E, 0x57,
	0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
	0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE,
}

// fmsVersion is the server version embedded in S1 for complex handshake.
var fmsVersion = [4]byte{0x04, 0x05, 0x00, 0x01}

func hmacSHA256(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// digestBlockStart returns the byte offset of the DigestBlock within a
// 1536-byte C1/S1 packet for the given scheme.
//   Scheme 0: DigestBlock first  → offset 8
//   Scheme 1: KeyBlock first     → offset 772
func digestBlockStart(scheme int) int {
	if scheme == 0 {
		return 8
	}
	return 772
}

// digestPos returns the absolute position of the embedded 32-byte digest
// within a 1536-byte C1/S1 packet.
//
// DigestBlock layout (764 bytes total):
//   [0:4]   digest_offset  (four bytes whose *sum* gives the offset, per RTMPDump)
//   [4:764] digest data    (760 bytes, digest lives at offset%728 within this region)
func digestPos(data []byte, scheme int) int {
	start := digestBlockStart(scheme)
	offset := uint32(data[start]) + uint32(data[start+1]) + uint32(data[start+2]) + uint32(data[start+3])
	return start + 4 + int(offset%(760-32))
}

// validateC1Complex checks whether C1 contains a valid complex-handshake
// digest for the given scheme. Returns (digest position, true) if valid.
func validateC1Complex(c1 []byte, scheme int) (int, bool) {
	pos := digestPos(c1, scheme)

	// Message is all of C1 except the 32-byte digest region (total 1504 bytes).
	msg := make([]byte, 1504)
	copy(msg[:pos], c1[:pos])
	copy(msg[pos:], c1[pos+32:])

	expected := hmacSHA256(msg, fpKey[:30])
	return pos, hmac.Equal(expected, c1[pos:pos+32])
}

// buildComplexS1 constructs a complex S1 packet (1536 bytes).
// Returns (s1, s1Digest, s1DigestPos, error).
func buildComplexS1(scheme int) ([]byte, []byte, int, error) {
	s1 := make([]byte, 1536)

	binary.BigEndian.PutUint32(s1[0:4], uint32(timeNow().UnixNano()/int64(time.Millisecond)))
	copy(s1[4:8], fmsVersion[:])

	if _, err := rand.Read(s1[8:]); err != nil {
		return nil, nil, 0, err
	}

	// Place digest_offset = 0 so the digest sits at the first possible position.
	start := digestBlockStart(scheme)
	binary.BigEndian.PutUint32(s1[start:start+4], 0)
	pos := start + 4 // 0 % 728 == 0

	// Sign S1 excluding the 32-byte digest region.
	msg := make([]byte, 1504)
	copy(msg[:pos], s1[:pos])
	copy(msg[pos:], s1[pos+32:])

	digest := hmacSHA256(msg, fmsKey[:36])
	copy(s1[pos:pos+32], digest)

	return s1, digest, pos, nil
}

// buildComplexS2 constructs the complex S2 packet (1536 bytes):
//   S2 = random_1504 || HMAC-SHA256(random_1504, HMAC-SHA256(c1Digest, fmsKey))
func buildComplexS2(c1Digest []byte) ([]byte, error) {
	digestKey := hmacSHA256(c1Digest, fmsKey)

	s2 := make([]byte, 1536)
	if _, err := rand.Read(s2[:1504]); err != nil {
		return nil, err
	}

	s2Digest := hmacSHA256(s2[:1504], digestKey)
	copy(s2[1504:], s2Digest)

	return s2, nil
}
