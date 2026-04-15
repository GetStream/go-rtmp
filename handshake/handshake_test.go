//
// Copyright (c) 2018- yutopp (yutopp@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at  https://www.boost.org/LICENSE_1_0.txt)
//

package handshake

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// startServer runs HandshakeWithClient in a goroutine, returning pipe ends for
// the client side and a channel that receives the server's return value.
func startServer(t *testing.T, config *Config) (clientW *io.PipeWriter, clientR *io.PipeReader, done <-chan error) {
	t.Helper()
	serverR, cw := io.Pipe()
	cr, serverW := io.Pipe()

	ch := make(chan error, 1)
	go func() {
		ch <- HandshakeWithClient(serverR, serverW, config)
		serverW.Close()
		serverR.Close()
	}()

	t.Cleanup(func() {
		cw.Close()
		cr.Close()
	})

	return cw, cr, ch
}

// makeSimpleC1 returns a 1536-byte C1 with peer version = 0 (simple handshake).
func makeSimpleC1(t *testing.T) []byte {
	t.Helper()
	c1 := make([]byte, 1536)
	binary.BigEndian.PutUint32(c1[0:4], 1000) // arbitrary timestamp
	// bytes 4-7: zero (peer version = 0)
	_, err := rand.Read(c1[8:])
	require.NoError(t, err)
	return c1
}

// makeComplexC1 returns a 1536-byte C1 with a valid HMAC digest for the given
// scheme, and the absolute position of that digest within the packet.
func makeComplexC1(t *testing.T, scheme int) (c1 []byte, digestPosition int) {
	t.Helper()
	c1 = make([]byte, 1536)
	binary.BigEndian.PutUint32(c1[0:4], 2000) // arbitrary timestamp
	// Non-zero peer version — signals complex handshake.
	c1[4], c1[5], c1[6], c1[7] = 0x09, 0x00, 0x7c, 0x02

	_, err := rand.Read(c1[8:])
	require.NoError(t, err)

	// Set digest_offset = 0 so the digest sits at the first valid position.
	start := digestBlockStart(scheme)
	binary.BigEndian.PutUint32(c1[start:start+4], 0)
	pos := start + 4

	// Compute and embed the digest.
	msg := make([]byte, 1504)
	copy(msg[:pos], c1[:pos])
	copy(msg[pos:], c1[pos+32:])
	digest := hmacSHA256(msg, fpKey[:30])
	copy(c1[pos:pos+32], digest)

	return c1, pos
}

// exchangeC0C1 writes C0+C1 to the server then reads back S0+S1+S2.
// Returns (s1, s2).
func exchangeC0C1(t *testing.T, cw io.Writer, cr io.Reader, c1 []byte) (s1, s2 []byte) {
	t.Helper()

	// Send C0 + C1.
	_, err := cw.Write([]byte{0x03})
	require.NoError(t, err)
	_, err = cw.Write(c1)
	require.NoError(t, err)

	// Read S0 + S1 + S2.
	buf := make([]byte, 1+1536+1536)
	_, err = io.ReadFull(cr, buf)
	require.NoError(t, err)

	require.Equal(t, byte(RTMPVersion), buf[0], "S0 must equal RTMP version")
	return buf[1:1537], buf[1537:3073]
}

// sendSimpleC2 sends C2 that echoes the random bytes from s1 (simple handshake).
func sendSimpleC2(t *testing.T, cw io.Writer, s1 []byte) {
	t.Helper()
	c2 := make([]byte, 1536)
	copy(c2[0:4], s1[0:4]) // time echo
	binary.BigEndian.PutUint32(c2[4:8], 9999)
	copy(c2[8:], s1[8:]) // random echo
	_, err := cw.Write(c2)
	require.NoError(t, err)
}

// TestHandshakeWithClient_Simple verifies the basic happy path: a client that
// sends C1 with a zero peer version triggers simple handshake and the server
// sends S0=0x03, S2 that echoes C1's random bytes.
func TestHandshakeWithClient_Simple(t *testing.T) {
	cw, cr, done := startServer(t, &Config{SkipHandshakeVerification: true})

	c1 := makeSimpleC1(t)
	s1, s2 := exchangeC0C1(t, cw, cr, c1)

	// S1 peer version must be zero in simple mode.
	require.Equal(t, []byte{0, 0, 0, 0}, s1[4:8], "S1 peer version must be zero for simple handshake")

	// S2 must echo C1: first 4 bytes = c1 time, bytes 8+ = c1 random.
	require.Equal(t, c1[0:4], s2[0:4], "S2.Time must equal C1.Time")
	require.Equal(t, c1[8:], s2[8:], "S2.RandomEcho must match C1.Random")

	// Send any C2 (verification is skipped).
	_, err := cw.Write(make([]byte, 1536))
	require.NoError(t, err)

	require.NoError(t, <-done)
	_ = s1
}

// TestHandshakeWithClient_Simple_ValidC2 verifies that simple C2 verification
// passes when the client correctly echoes S1's random bytes.
func TestHandshakeWithClient_Simple_ValidC2(t *testing.T) {
	cw, cr, done := startServer(t, &Config{SkipHandshakeVerification: false})

	c1 := makeSimpleC1(t)
	s1, _ := exchangeC0C1(t, cw, cr, c1)

	sendSimpleC2(t, cw, s1)

	require.NoError(t, <-done)
}

// TestHandshakeWithClient_Simple_InvalidC2 verifies that simple C2 verification
// fails when the client sends random bytes that do not match S1.
func TestHandshakeWithClient_Simple_InvalidC2(t *testing.T) {
	cw, cr, done := startServer(t, &Config{SkipHandshakeVerification: false})

	c1 := makeSimpleC1(t)
	_, _ = exchangeC0C1(t, cw, cr, c1)

	// C2 with completely random bytes — will not match S1.
	badC2 := make([]byte, 1536)
	_, err := rand.Read(badC2)
	require.NoError(t, err)
	_, err = cw.Write(badC2)
	require.NoError(t, err)

	require.Error(t, <-done, "server must reject mismatched C2 random echo")
}

// TestHandshakeWithClient_Complex_Scheme0 verifies that a valid complex C1
// using scheme 0 triggers complex handshake: S1 carries the FMS version and a
// verifiable digest, and S2 follows the HMAC derivation from the spec.
func TestHandshakeWithClient_Complex_Scheme0(t *testing.T) {
	testComplexHandshake(t, 0)
}

// TestHandshakeWithClient_Complex_Scheme1 is the same as Scheme0 but the C1
// DigestBlock is placed at the scheme-1 offset (byte 772).
func TestHandshakeWithClient_Complex_Scheme1(t *testing.T) {
	testComplexHandshake(t, 1)
}

func testComplexHandshake(t *testing.T, scheme int) {
	t.Helper()
	cw, cr, done := startServer(t, &Config{SkipHandshakeVerification: true})

	c1, c1DigestPos := makeComplexC1(t, scheme)
	s1, s2 := exchangeC0C1(t, cw, cr, c1)

	// S1 must carry the FMS server version (non-zero peer version).
	require.Equal(t, fmsVersion[:], s1[4:8], "S1 must contain FMS server version")

	// S1 digest must be valid: HMAC-SHA256(S1_without_digest, fmsKey[:36]).
	s1DigestPos := digestPos(s1, scheme)
	s1Msg := make([]byte, 1504)
	copy(s1Msg[:s1DigestPos], s1[:s1DigestPos])
	copy(s1Msg[s1DigestPos:], s1[s1DigestPos+32:])
	expectedS1Digest := hmacSHA256(s1Msg, fmsKey[:36])
	require.Equal(t, expectedS1Digest, s1[s1DigestPos:s1DigestPos+32],
		"S1 digest must be HMAC-SHA256(S1_without_digest, FMSKey[:36])")

	// S2 tail (last 32 bytes) must be HMAC-SHA256(S2[:1504], digestKey)
	// where digestKey = HMAC-SHA256(C1_digest, fmsKey).
	c1Digest := c1[c1DigestPos : c1DigestPos+32]
	digestKey := hmacSHA256(c1Digest, fmsKey)
	expectedS2Tail := hmacSHA256(s2[:1504], digestKey)
	require.Equal(t, expectedS2Tail, s2[1504:],
		"S2 tail must be HMAC-SHA256(S2[:1504], digestKey)")

	// Send any C2.
	_, err := cw.Write(make([]byte, 1536))
	require.NoError(t, err)

	require.NoError(t, <-done)
}

// TestHandshakeWithClient_Complex_FallbackOnZeroPeerVersion verifies that a C1
// whose peer-version bytes are all zero triggers simple handshake even when the
// rest of the packet looks like complex data.
func TestHandshakeWithClient_Complex_FallbackOnZeroPeerVersion(t *testing.T) {
	cw, cr, done := startServer(t, &Config{SkipHandshakeVerification: true})

	// Build a complex-looking C1 but zero out the peer version.
	c1, _ := makeComplexC1(t, 0)
	c1[4], c1[5], c1[6], c1[7] = 0, 0, 0, 0 // zero peer version

	s1, s2 := exchangeC0C1(t, cw, cr, c1)

	// Server must fall back to simple: S1 peer version = zero.
	require.Equal(t, []byte{0, 0, 0, 0}, s1[4:8],
		"S1 peer version must be zero when falling back to simple")

	// S2 must echo C1 random (simple S2 behavior).
	require.Equal(t, c1[8:], s2[8:], "S2 must echo C1 random on simple fallback")

	_, err := cw.Write(make([]byte, 1536))
	require.NoError(t, err)

	require.NoError(t, <-done)
}

// TestHandshakeWithClient_Complex_FallbackOnInvalidDigest verifies that a C1
// with a non-zero peer version but an invalid digest (neither scheme validates)
// causes the server to fall back to simple handshake.
func TestHandshakeWithClient_Complex_FallbackOnInvalidDigest(t *testing.T) {
	cw, cr, done := startServer(t, &Config{SkipHandshakeVerification: true})

	// Build a C1 with non-zero peer version but deliberately wrong digest bytes.
	c1 := make([]byte, 1536)
	binary.BigEndian.PutUint32(c1[0:4], 3000)
	c1[4], c1[5], c1[6], c1[7] = 0x09, 0x00, 0x7c, 0x02 // non-zero peer version
	_, err := rand.Read(c1[8:])
	require.NoError(t, err)
	// Digest bytes are random → validation will fail for both schemes.

	s1, s2 := exchangeC0C1(t, cw, cr, c1)

	// Server must fall back to simple.
	require.Equal(t, []byte{0, 0, 0, 0}, s1[4:8],
		"S1 peer version must be zero when falling back to simple")
	require.Equal(t, c1[8:], s2[8:],
		"S2 must echo C1 random on simple fallback")

	_, err = cw.Write(make([]byte, 1536))
	require.NoError(t, err)

	require.NoError(t, <-done)

	// Verify: validating this C1 with any scheme must fail.
	_, ok0 := validateC1FP9(c1, 0)
	_, ok1 := validateC1FP9(c1, 1)
	require.False(t, ok0 || ok1, "C1 with random bytes should not pass complex validation")
}
