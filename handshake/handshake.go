//
// Copyright (c) 2018- yutopp (yutopp@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at  https://www.boost.org/LICENSE_1_0.txt)
//

package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"time"

	"github.com/pkg/errors"
)

type S0C0 byte // RTMP Version

type S1C1 struct {
	Time    uint32
	Version [4]byte
	Random  [1528]byte
}

type S2C2 struct {
	Time   uint32
	Time2  uint32
	Random [1528]byte
}

var RTMPVersion = 3

var Version = [4]byte{0, 0, 0, 0} // TODO: fix

var timeNow = time.Now // For mock

type Config struct {
	SkipHandshakeVerification bool
}

func HandshakeWithClient(r io.Reader, w io.Writer, config *Config) error {
	// Recv C0 (1 byte: RTMP version).
	c0 := make([]byte, 1)
	if _, err := io.ReadFull(r, c0); err != nil {
		return err
	}
	// TODO: check c0 RTMP version

	// Recv C1 (1536 bytes). We need the full raw packet to detect and validate
	// complex handshake before sending anything (spec §4).
	c1 := make([]byte, 1536)
	if _, err := io.ReadFull(r, c1); err != nil {
		return err
	}

	// Determine handshake mode by inspecting the peer version (bytes 4–7 of C1).
	// A zero peer version means simple handshake; non-zero triggers complex
	// validation with scheme-0 → scheme-1 → simple fallback (spec §6.1, §8).
	var (
		useComplex    bool
		complexScheme int
		c1DigestPos   int
		s1Digest      []byte
	)
	c1HasVersion := c1[4]|c1[5]|c1[6]|c1[7] != 0
	if c1HasVersion {
		for _, scheme := range []int{0, 1} {
			if pos, ok := validateC1Complex(c1, scheme); ok {
				useComplex = true
				complexScheme = scheme
				c1DigestPos = pos
				break
			}
		}
		if !useComplex {
			log.Printf("handshake: C1 has non-zero version %x but failed complex validation (scheme 0 and 1); falling back to simple handshake", c1[4:8])
		}
	}
	log.Printf("handshake: mode=%s c0_version=%d c1_version=%x c1_time=%x useComplex=%v complexScheme=%d",
		func() string {
			if useComplex {
				return "complex"
			}
			return "simple"
		}(),
		c0[0], c1[4:8], c1[0:4], useComplex, complexScheme,
	)

	// Build S0 + S1 + S2 in one buffer and send atomically.
	out := make([]byte, 1+1536+1536)
	out[0] = byte(RTMPVersion) // S0

	var s1Bytes []byte

	if useComplex {
		var s1DigestPos int
		var err error
		s1Bytes, s1Digest, s1DigestPos, err = buildComplexS1(complexScheme)
		if err != nil {
			return err
		}
		_ = s1DigestPos

		s2Bytes, err := buildComplexS2(c1[c1DigestPos : c1DigestPos+32])
		if err != nil {
			return err
		}

		copy(out[1:1537], s1Bytes)
		copy(out[1537:], s2Bytes)
	} else {
		// Simple S1: zero peer version, random bytes.
		s1Bytes = make([]byte, 1536)
		binary.BigEndian.PutUint32(s1Bytes[0:4], uint32(timeNow().UnixNano()/int64(time.Millisecond)))
		// bytes 4–7: zero (Version = simple marker)
		if _, err := rand.Read(s1Bytes[8:]); err != nil {
			return err
		}

		// Simple S2: echo of C1 (time + random bytes).
		s2Bytes := make([]byte, 1536)
		copy(s2Bytes[0:4], c1[0:4]) // C1.Time
		binary.BigEndian.PutUint32(s2Bytes[4:8], uint32(timeNow().UnixNano()/int64(time.Millisecond)))
		copy(s2Bytes[8:], c1[8:]) // C1.Random echo

		copy(out[1:1537], s1Bytes)
		copy(out[1537:], s2Bytes)
	}

	if _, err := w.Write(out); err != nil {
		return err
	}

	// Recv C2 (1536 bytes).
	c2 := make([]byte, 1536)
	if _, err := io.ReadFull(r, c2); err != nil {
		return err
	}

	if config.SkipHandshakeVerification {
		return nil
	}

	if useComplex {
		// C2 verification is non-fatal per spec §7 — compute and compare but
		// always continue regardless of the result.
		fpDigestKey := hmacSHA256(s1Digest, fpKey)
		expected := hmacSHA256(c2[:1504], fpDigestKey)
		if !bytes.Equal(expected, c2[1504:]) {
			log.Printf("handshake: complex C2 digest mismatch (advisory, continuing): scheme=%d c2_digest=%x expected=%x",
				complexScheme, c2[1504:], expected)
		} else {
			log.Printf("handshake: complex C2 digest OK: scheme=%d", complexScheme)
		}
		return nil
	}

	// Simple handshake: C2.Random (bytes 8–1535) must echo S1.Random.
	if !bytes.Equal(c2[8:], s1Bytes[8:]) {
		firstMismatch := -1
		for i := 8; i < 1536; i++ {
			if c2[i] != s1Bytes[i] {
				firstMismatch = i
				break
			}
		}
		return errors.Errorf(
			"Random echo is not matched (simple handshake, c1_had_version=%v):"+
				" c0_version=%d"+
				" c1_version=%x c1_time=%x c1_random[:8]=%x"+
				" s1_version=%x s1_time=%x s1_random[:8]=%x"+
				" c2_time=%x c2_time2=%x c2_random[:8]=%x"+
				" first_mismatch_byte=%d",
			c1HasVersion,
			c0[0],
			c1[4:8], c1[0:4], c1[8:16],
			s1Bytes[4:8], s1Bytes[0:4], s1Bytes[8:16],
			c2[0:4], c2[4:8], c2[8:16],
			firstMismatch,
		)
	}

	return nil
}

func HandshakeWithServer(r io.Reader, w io.Writer, config *Config) error {
	d := NewDecoder(r)
	e := NewEncoder(w)

	// Send C0
	c0 := S0C0(RTMPVersion)
	if err := e.EncodeS0C0(&c0); err != nil {
		return errors.Wrap(err, "Failed to encode c0")
	}

	// Send C1
	c1 := S1C1{
		Time: uint32(timeNow().UnixNano() / int64(time.Millisecond)),
	}
	copy(c1.Version[:], Version[:])
	if _, err := rand.Read(c1.Random[:]); err != nil { // Random Seq
		return err
	}
	if err := e.EncodeS1C1(&c1); err != nil {
		return errors.Wrap(err, "Failed to encode c1")
	}

	// Recv S0
	var s0 S0C0
	if err := d.DecodeS0C0(&s0); err != nil {
		return errors.Wrap(err, "Failed to decode s0")
	}

	// TODO: check s0 RTMP version

	// Recv S1
	var s1 S1C1
	if err := d.DecodeS1C1(&s1); err != nil {
		return errors.Wrap(err, "Failed to decode s1")
	}

	// TODO: check s1 Server version. e.g. [9 0 124 2]

	// Recv S2
	var s2 S2C2
	if err := d.DecodeS2C2(&s2); err != nil {
		return errors.Wrap(err, "Failed to decode s2")
	}

	// Send C2
	c2 := S2C2{
		Time:  c1.Time,
		Time2: uint32(timeNow().UnixNano() / int64(time.Millisecond)),
	}
	copy(c2.Random[:], s1.Random[:]) // echo s1 random
	if err := e.EncodeS2C2(&c2); err != nil {
		return errors.Wrap(err, "Failed to encode c2")
	}

	if config.SkipHandshakeVerification {
		return nil
	}

	// Check random echo
	if !bytes.Equal(s2.Random[:], c1.Random[:]) {
		return errors.New("Random echo is not matched")
	}

	return nil
}
