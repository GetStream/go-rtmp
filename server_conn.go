//
// Copyright (c) 2018- yutopp (yutopp@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at  https://www.boost.org/LICENSE_1_0.txt)
//

package rtmp

import (
	"github.com/guerinoni/go-rtmp/handshake"
	"github.com/pkg/errors"
)

// serverConn A wrapper of a connection. It prorives server-side specific features.
type serverConn struct {
	conn *Conn
}

func newServerConn(conn *Conn) *serverConn {
	return &serverConn{
		conn: conn,
	}
}

func (sc *serverConn) Serve() error {
	hs := handshake.HandshakeServer{}
	if err := hs.Handshake(sc.conn.rwc); err != nil {
		return errors.Wrap(err, "Failed to handshake")
	}

	ctrlStream, err := sc.conn.streams.Create(ControlStreamID)
	if err != nil {
		if err := sc.conn.handler.OnError(errors.Wrap(err, "Failed to create control stream")); err != nil {
			return errors.Wrap(err, "Failed to create control stream")
		}
		return errors.Wrap(err, "Failed to create control stream")
	}
	ctrlStream.handler.ChangeState(streamStateServerNotConnected)

	sc.conn.streamer.controlStreamWriter = ctrlStream.Write

	if sc.conn.handler != nil {
		sc.conn.handler.OnServe(sc.conn)
	}

	err = sc.conn.handleMessageLoop()
	if err != nil {
		err = errors.New("handleMessageLoop returned error: " + err.Error())
		if sc.conn.handler != nil {
			return sc.conn.handler.OnError(err)
		}
		return errors.New("error occured while processing the data")
	}

	return nil
}

func (sc *serverConn) Close() error {
	return sc.conn.Close()
}
