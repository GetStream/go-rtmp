package handshake

import (
	"encoding/binary"
	"io"
	"time"
)

type HandshakeClientSimple struct {
	buf []byte
}

func (c *HandshakeClientSimple) WriteC0C1(writer io.Writer) error {
	c.buf = make([]byte, c0c1Len)
	c.buf[0] = version
	binary.BigEndian.PutUint32(c.buf[1:5], uint32(time.Now().UnixNano()))
	binary.BigEndian.PutUint32(c.buf[5:9], 0)
	random1528(c.buf[9:])

	_, err := writer.Write(c.buf)
	return err
}

func (c *HandshakeClientSimple) ReadS0S1(reader io.Reader) error {
	_, err := io.ReadAtLeast(reader, c.buf, s0s1Len)
	return err
}

func (c *HandshakeClientSimple) WriteC2(writer io.Writer) error {
	// use s1 as c2
	_, err := writer.Write(c.buf[1:])
	return err
}

func (c *HandshakeClientSimple) ReadS2(reader io.Reader) error {
	_, err := io.ReadAtLeast(reader, c.buf, s2Len)
	return err
}
