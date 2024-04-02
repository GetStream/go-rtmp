//
// Copyright (c) 2018- yutopp (yutopp@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at  https://www.boost.org/LICENSE_1_0.txt)
//

package message

import "github.com/pkg/errors"

type NetStreamPublish struct {
	CommandObject  interface{}
	PublishingName string
	PublishingType string
}

func (t *NetStreamPublish) FromArgs(args ...interface{}) error {
	// command := args[0] // will be nil

	var ok bool
	var n string

	n, ok = args[1].(string)
	if !ok {
		return errors.New("Failed to map NetStreamPublish: args[1] is not a string.")
	}
	t.PublishingName = n

	n, ok = args[2].(string)
	if !ok {
		return errors.New("Failed to map NetStreamPublish: args[2] is not a string.")
	}

	t.PublishingType = n
	return nil
}

func (t *NetStreamPublish) ToArgs(ty EncodingType) ([]interface{}, error) {
	return []interface{}{
		nil, // Always nil
		t.PublishingName,
		t.PublishingType,
	}, nil
}

type NetStreamPlay struct {
	CommandObject interface{}
	StreamName    string
	Start         int64
}

func (t *NetStreamPlay) FromArgs(args ...interface{}) error {
	// command := args[0] // will be nil

	var ok bool

	n, ok := args[1].(string)
	if !ok {
		return errors.New("Failed to map NetStreamPlay: args[1] is not a string.")
	}
	t.StreamName = n

	i, ok := args[2].(int64)
	if !ok {
		return errors.New("Failed to map NetStreamPlay: args[2] is not a int64.")
	}
	t.Start = i

	return nil
}

func (t *NetStreamPlay) ToArgs(ty EncodingType) ([]interface{}, error) {
	panic("Not implemented")
}

type NetStreamOnStatusLevel string

const (
	NetStreamOnStatusLevelStatus NetStreamOnStatusLevel = "status"
	NetStreamOnStatusLevelError  NetStreamOnStatusLevel = "error"
)

type NetStreamOnStatusCode string

const (
	NetStreamOnStatusCodeConnectSuccess      NetStreamOnStatusCode = "NetStream.Connect.Success"
	NetStreamOnStatusCodeConnectFailed       NetStreamOnStatusCode = "NetStream.Connect.Failed"
	NetStreamOnStatusCodeMuticastStreamReset NetStreamOnStatusCode = "NetStream.MulticastStream.Reset"
	NetStreamOnStatusCodePlayStart           NetStreamOnStatusCode = "NetStream.Play.Start"
	NetStreamOnStatusCodePlayFailed          NetStreamOnStatusCode = "NetStream.Play.Failed"
	NetStreamOnStatusCodePlayComplete        NetStreamOnStatusCode = "NetStream.Play.Complete"
	NetStreamOnStatusCodePublishBadName      NetStreamOnStatusCode = "NetStream.Publish.BadName"
	NetStreamOnStatusCodePublishFailed       NetStreamOnStatusCode = "NetStream.Publish.Failed"
	NetStreamOnStatusCodePublishStart        NetStreamOnStatusCode = "NetStream.Publish.Start"
	NetStreamOnStatusCodeUnpublishSuccess    NetStreamOnStatusCode = "NetStream.Unpublish.Success"
)

type NetStreamOnStatus struct {
	InfoObject NetStreamOnStatusInfoObject
}

type NetStreamOnStatusInfoObject struct {
	Level       NetStreamOnStatusLevel
	Code        NetStreamOnStatusCode
	Description string
}

func (t *NetStreamOnStatus) FromArgs(args ...interface{}) error {
	panic("Not implemented")
}

func (t *NetStreamOnStatus) ToArgs(ty EncodingType) ([]interface{}, error) {
	info := make(map[string]interface{})
	info["level"] = t.InfoObject.Level
	info["code"] = t.InfoObject.Code
	info["description"] = t.InfoObject.Description

	return []interface{}{
		nil, // Always nil
		info,
	}, nil
}

type NetStreamDeleteStream struct {
	StreamID uint32
}

func (t *NetStreamDeleteStream) FromArgs(args ...interface{}) error {
	// args[0] is unknown, ignore
	s, ok := args[1].(uint32)
	if !ok {
		return errors.New("Failed to map NetStreamDeleteStream: args[1] is not a uint32.")
	}

	t.StreamID = s
	return nil
}

func (t *NetStreamDeleteStream) ToArgs(ty EncodingType) ([]interface{}, error) {
	return []interface{}{
		nil, // no command object
		t.StreamID,
	}, nil
}

type NetStreamFCPublish struct {
	StreamName string
}

func (t *NetStreamFCPublish) FromArgs(args ...interface{}) error {
	// args[0] is unknown, ignore
	n, ok := args[1].(string)
	if !ok {
		return errors.New("Failed to map NetStreamFCPublish: args[1] is not a string.")
	}

	t.StreamName = n
	return nil
}

func (t *NetStreamFCPublish) ToArgs(ty EncodingType) ([]interface{}, error) {
	return []interface{}{
		nil, // no command object
		t.StreamName,
	}, nil
}

type NetStreamFCUnpublish struct {
	StreamName string
}

func (t *NetStreamFCUnpublish) FromArgs(args ...interface{}) error {
	// args[0] is unknown, ignore
	n, ok := args[1].(string)
	if !ok {
		return errors.New("Failed to map NetStreamFCUnpublish: args[1] is not a string.")
	}

	t.StreamName = n
	return nil
}

func (t *NetStreamFCUnpublish) ToArgs(ty EncodingType) ([]interface{}, error) {
	return []interface{}{
		nil, // no command object
		t.StreamName,
	}, nil
}

type NetStreamReleaseStream struct {
	StreamName string
}

func (t *NetStreamReleaseStream) FromArgs(args ...interface{}) error {
	// args[0] is unknown, ignore
	n, ok := args[1].(string)
	if !ok {
		return errors.New("Failed to map NetStreamFCUnpublish: args[1] is not a string.")
	}

	t.StreamName = n
	return nil
}

func (t *NetStreamReleaseStream) ToArgs(ty EncodingType) ([]interface{}, error) {
	return []interface{}{
		nil, // no command object
		t.StreamName,
	}, nil
}

// NetStreamSetDataFrame - send data. AmfData is what will be encoded.
type NetStreamSetDataFrame struct {
	Payload []byte
	AmfData interface{}
}

func (t *NetStreamSetDataFrame) FromArgs(args ...interface{}) error {
	p, ok := args[0].([]byte)
	if !ok {
		return errors.New("Failed to map NetStreamSetDataFrame: args[0] is not a []byte.")
	}

	t.Payload = p
	return nil
}

func (t *NetStreamSetDataFrame) ToArgs(ty EncodingType) ([]interface{}, error) {
	return []interface{}{
		"onMetaData",
		t.AmfData,
	}, nil
}

type NetStreamGetStreamLength struct {
	StreamName string
}

func (t *NetStreamGetStreamLength) FromArgs(args ...interface{}) error {
	// args[0] is unknown, ignore
	s, ok := args[1].(string)
	if !ok {
		return errors.New("Failed to map NetStreamGetStreamLength: args[1] is not a string.")
	}

	t.StreamName = s
	return nil
}

func (t *NetStreamGetStreamLength) ToArgs(ty EncodingType) ([]interface{}, error) {
	return []interface{}{
		nil, // no command object
		t.StreamName,
	}, nil
}

type NetStreamPing struct{}

func (t *NetStreamPing) FromArgs(args ...interface{}) error {
	// args[0] is unknown, ignore

	return nil
}

func (t *NetStreamPing) ToArgs(ty EncodingType) ([]interface{}, error) {
	return []interface{}{
		nil, // no command object
	}, nil
}

type NetStreamCloseStream struct{}

func (t *NetStreamCloseStream) FromArgs(args ...interface{}) error {
	// args[0] is unknown, ignore

	return nil
}

func (t *NetStreamCloseStream) ToArgs(ty EncodingType) ([]interface{}, error) {
	return []interface{}{
		nil, // no command object
	}, nil
}
