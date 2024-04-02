//
// Copyright (c) 2018- yutopp (yutopp@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at  https://www.boost.org/LICENSE_1_0.txt)
//

package handshake

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/sirupsen/logrus"
)

// https://rtmp.veriskope.com/docs/spec

// +-------------+                           +-------------+
// |    Client   |       TCP/IP Network      |    Server   |
// +-------------+            |              +-------------+
//       |                    |                     |
//  Uninitialized             |               Uninitialized
//       |          C0        |                     |
//       |------------------->|         C0          |
//       |                    |-------------------->|
//       |          C1        |                     |
//       |------------------->|         S0          |
//       |                    |<--------------------|
//       |                    |         S1          |
//  Version sent              |<--------------------|
//       |          S0        |                     |
//       |<-------------------|                     |
//       |          S1        |                     |
//       |<-------------------|                Version sent
//       |                    |         C1          |
//       |                    |-------------------->|
//       |          C2        |                     |
//       |------------------->|         S2          |
//       |                    |<--------------------|
//    Ack sent                |                  Ack Sent
//       |          S2        |                     |
//       |<-------------------|                     |
//       |                    |         C2          |
//       |                    |-------------------->|
//  Handshake Done            |               Handshake Done
//       |                    |                     |

// C1/S1
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        time (4 bytes)                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        zero (4 bytes)                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         random bytes (1528 bytes)             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         random bytes                          |
// |                           (cont)                              |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// C2/S2
// 0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        time (4 bytes)                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        time2 (4 bytes)                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          random echo (1528 bytes)             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          random echo                          |
// |                            (cont)                             |
// |                              ...                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

const version = uint8(3)

const (
	c0c1Len   = 1537
	c2Len     = 1536
	s0s1Len   = 1537
	s1Len     = 1536
	s2Len     = 1536
	s0s1s2Len = 3073
)

const (
	clientPartKeyLen = 30
	clientFullKeyLen = 62
	serverPartKeyLen = 36
	serverFullKeyLen = 68
	keyLen           = 32
)

var (
	clientVersionMockFromFfmpeg = []byte{9, 0, 124, 2} // emulated Flash client version - 9.0.124.2 on Linux
	serverVersion               = []byte{0x0D, 0x0E, 0x0A, 0x0D}
)

// 30+32.
var clientKey = []byte{
	'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
	'F', 'l', 'a', 's', 'h', ' ', 'P', 'l', 'a', 'y', 'e', 'r', ' ',
	'0', '0', '1',

	0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1,
	0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
	0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE,
}

// 36+32.
var serverKey = []byte{
	'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
	'F', 'l', 'a', 's', 'h', ' ', 'M', 'e', 'd', 'i', 'a', ' ',
	'S', 'e', 'r', 'v', 'e', 'r', ' ',
	'0', '0', '1',

	0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1,
	0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
	0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE,
}

var random1528Buf []byte

func init() {
	random1528Buf = make([]byte, 1528)
	hack := []byte(fmt.Sprintf("random buf of rtmp handshake gen by %s", time.Now()))
	for i := 0; i < 1528; i += len(hack) {
		copy(random1528Buf[i:], hack)
	}
}

// c0c1 clientPartKey serverFullKey.
// s0s1 serverPartKey clientFullKey.
func parseChallenge(b []byte, peerKey []byte, key []byte) []byte {
	ver := binary.BigEndian.Uint32(b[5:])
	if ver == 0 {
		logrus.StandardLogger().Debug("handshake simple mode.")
		return nil
	}

	offs := findDigest(b[1:], 764+8, peerKey)
	if offs == -1 {
		offs = findDigest(b[1:], 8, peerKey)
	}
	if offs == -1 {
		logrus.StandardLogger().WithField("peerKey", peerKey).Debug("get digest offs failed. roll back to try simple handshake.")
		return nil
	}
	logrus.StandardLogger().WithField("offs", offs).Debug("handshake complex mode.")

	// use c0c1 digest to make a new digest
	digest := makeDigest(b[1+offs:1+offs+keyLen], key)

	return digest
}

func findDigest(b []byte, base int, key []byte) int {
	// calc offs
	offs := int(b[base]) + int(b[base+1]) + int(b[base+2]) + int(b[base+3])
	offs = (offs % 728) + base + 4
	// calc digest
	digest := make([]byte, keyLen)
	makeDigestWithoutCenterPart(b, offs, key, digest)
	// compare origin digest in buffer with calced digest
	if bytes.Equal(digest, b[offs:offs+keyLen]) {
		return offs
	}
	return -1
}

// <b> could be `c1` or `s1` or `s2`.
func makeDigestWithoutCenterPart(b []byte, offs int, key []byte, out []byte) {
	mac := hmac.New(sha256.New, key)
	// left
	if offs != 0 {
		mac.Write(b[:offs])
	}
	// right
	if len(b)-offs-keyLen > 0 {
		mac.Write(b[offs+keyLen:])
	}
	// calc
	copy(out, mac.Sum(nil))
}

func makeDigest(b []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	return mac.Sum(nil)
}

func random1528(out []byte) {
	copy(out, random1528Buf)
}

type Handshaker interface {
	WriteC0C1(io.Writer) error
	ReadS0S1(io.Reader) error
	WriteC2(io.Writer) error
	ReadS2(io.Reader) error
}

func Handshake(c Handshaker, rwc io.ReadWriteCloser) error {
	if err := c.WriteC0C1(rwc); err != nil {
		return err
	}

	if err := c.ReadS0S1(rwc); err != nil {
		return err
	}

	if err := c.WriteC2(rwc); err != nil {
		return err
	}

	if err := c.ReadS2(rwc); err != nil {
		return err
	}

	return nil
}
