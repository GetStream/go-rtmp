package main

import (
	"bytes"
	"context"
	"fmt"

	"github.com/guerinoni/go-rtmp"
	rtmpmsg "github.com/guerinoni/go-rtmp/message"
	flvtag "github.com/yutopp/go-flv/tag"
)

func onEventCallback(conn *rtmp.Conn, streamID uint32) func(flv *flvtag.FlvTag) error {
	return func(flv *flvtag.FlvTag) error {
		buf := new(bytes.Buffer)

		switch flv.Data.(type) {
		case *flvtag.AudioData:
			d, ok := flv.Data.(*flvtag.AudioData)
			if !ok {
				return fmt.Errorf("invalid data type: AudioData")
			}

			// Consume flv payloads (d)
			if err := flvtag.EncodeAudioData(buf, d); err != nil {
				return err
			}

			// TODO: Fix these values
			ctx := context.Background()
			chunkStreamID := 5
			return conn.Write(ctx, chunkStreamID, flv.Timestamp, &rtmp.ChunkMessage{
				StreamID: streamID,
				Message: &rtmpmsg.AudioMessage{
					Payload: buf,
				},
			})

		case *flvtag.VideoData:
			d, ok := flv.Data.(*flvtag.VideoData)
			if !ok {
				return fmt.Errorf("invalid data type: VideoData")
			}

			// Consume flv payloads (d)
			if err := flvtag.EncodeVideoData(buf, d); err != nil {
				return err
			}

			// TODO: Fix these values
			ctx := context.Background()
			chunkStreamID := 6
			return conn.Write(ctx, chunkStreamID, flv.Timestamp, &rtmp.ChunkMessage{
				StreamID: streamID,
				Message: &rtmpmsg.VideoMessage{
					Payload: buf,
				},
			})

		case *flvtag.ScriptData:
			d, ok := flv.Data.(*flvtag.ScriptData)
			if !ok {
				return fmt.Errorf("invalid data type: ScriptData")
			}

			// Consume flv payloads (d)
			if err := flvtag.EncodeScriptData(buf, d); err != nil {
				return err
			}

			// TODO: hide these implementation
			amdBuf := new(bytes.Buffer)
			amfEnc := rtmpmsg.NewAMFEncoder(amdBuf, rtmpmsg.EncodingTypeAMF0)
			if err := rtmpmsg.EncodeBodyAnyValues(amfEnc, &rtmpmsg.NetStreamSetDataFrame{
				Payload: buf.Bytes(),
			}); err != nil {
				return err
			}

			// TODO: Fix these values
			ctx := context.Background()
			chunkStreamID := 8
			return conn.Write(ctx, chunkStreamID, flv.Timestamp, &rtmp.ChunkMessage{
				StreamID: streamID,
				Message: &rtmpmsg.DataMessage{
					Name:     "@setDataFrame", // TODO: fix
					Encoding: rtmpmsg.EncodingTypeAMF0,
					Body:     amdBuf,
				},
			})

		default:
			panic("unreachable")
		}
	}
}
