package handshake

import (
	"encoding/binary"
	"io"
)

type HandshakeClientComplex struct {
	buf []byte
}

func (c *HandshakeClientComplex) WriteC0C1(writer io.Writer) error {
	c.buf = make([]byte, c0c1Len)

	c.buf[0] = version
	// mock ffmpeg
	binary.BigEndian.PutUint32(c.buf[1:5], 0)
	copy(c.buf[5:9], clientVersionMockFromFfmpeg)
	random1528(c.buf[9:])

	offs := int(c.buf[9]) + int(c.buf[10]) + int(c.buf[11]) + int(c.buf[12])
	offs = (offs % 728) + 12
	makeDigestWithoutCenterPart(c.buf[1:c0c1Len], offs, clientKey[:clientPartKeyLen], c.buf[1+offs:])

	_, err := writer.Write(c.buf)
	return err
}

func (c *HandshakeClientComplex) ReadS0S1(reader io.Reader) error {
	s0s1 := make([]byte, s0s1Len)
	if _, err := io.ReadAtLeast(reader, s0s1, s0s1Len); err != nil {
		return err
	}

	c2key := parseChallenge(s0s1, serverKey[:serverPartKeyLen], clientKey[:clientFullKeyLen])

	// simple mode
	if c2key == nil {
		// use s1 as c2
		copy(c.buf, s0s1[1:])
		return nil
	}

	// complex mode
	random1528(c.buf)
	replayOffs := c2Len - keyLen
	makeDigestWithoutCenterPart(c.buf[:c2Len], replayOffs, c2key, c.buf[replayOffs:replayOffs+keyLen])
	return nil
}

func (c *HandshakeClientComplex) WriteC2(writer io.Writer) error {
	_, err := writer.Write(c.buf[:c2Len])
	return err
}

func (c *HandshakeClientComplex) ReadS2(reader io.Reader) error {
	_, err := io.ReadAtLeast(reader, c.buf, s2Len)
	return err
}
