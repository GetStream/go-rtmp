package handshake

import (
	"encoding/binary"
	"io"
	"time"
)

type HandshakeServer struct {
	isSimpleMode bool
	s0s1s2       []byte
}

func (s *HandshakeServer) ReadC0C1(reader io.Reader) (err error) {
	c0c1 := make([]byte, c0c1Len)
	if _, err = io.ReadAtLeast(reader, c0c1, c0c1Len); err != nil {
		return err
	}

	s.s0s1s2 = make([]byte, s0s1s2Len)

	s2key := parseChallenge(c0c1, clientKey[:clientPartKeyLen], serverKey[:serverFullKeyLen])
	s.isSimpleMode = len(s2key) == 0

	s.s0s1s2[0] = version

	s1 := s.s0s1s2[1:]
	s2 := s.s0s1s2[s0s1Len:]

	binary.BigEndian.PutUint32(s1, uint32(time.Now().UnixNano()))
	random1528(s1[8:])

	if s.isSimpleMode {
		// s1
		binary.BigEndian.PutUint32(s1[4:], 0)

		copy(s2, c0c1[1:])
	} else {
		// s1
		copy(s1[4:], serverVersion)

		offs := int(s1[8]) + int(s1[9]) + int(s1[10]) + int(s1[11])
		offs = (offs % 728) + 12
		makeDigestWithoutCenterPart(s.s0s1s2[1:s0s1Len], offs, serverKey[:serverPartKeyLen], s.s0s1s2[1+offs:])

		// s2
		// make digest to s2 suffix position
		random1528(s2)

		replyOffs := s2Len - keyLen
		makeDigestWithoutCenterPart(s2, replyOffs, s2key, s2[replyOffs:])
	}

	return nil
}

func (s *HandshakeServer) WriteS0S1S2(writer io.Writer) error {
	_, err := writer.Write(s.s0s1s2)
	return err
}

func (s *HandshakeServer) ReadC2(reader io.Reader) error {
	c2 := make([]byte, c2Len)
	if _, err := io.ReadAtLeast(reader, c2, c2Len); err != nil {
		return err
	}
	return nil
}

func (s *HandshakeServer) Handshake(rwc io.ReadWriteCloser) error {
	if err := s.ReadC0C1(rwc); err != nil {
		return err
	}

	if err := s.WriteS0S1S2(rwc); err != nil {
		return err
	}

	if err := s.ReadC2(rwc); err != nil {
		return err
	}

	return nil
}
