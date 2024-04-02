# go-rtmp

RTMP 1.0 server/client library written in Go.

## Tested on
- OBS Studio
- restream.io
- ffmpeg
- gstreamer (gst-launch)

## Installation

```
go get github.com/guerinoni/go-rtmp
```

See also [server_demo](https://github.com/guerinoni/go-rtmp/tree/master/example/server_demo) and [client_demo](https://github.com/guerinoni/go-rtmp/blob/master/example/client_demo/main.go).

## Documentation

- https://rtmp.veriskope.com/docs/spec

## NOTES

### How to limit bitrates or set timeouts

- Please use [yutopp/go-iowrap](https://github.com/yutopp/go-iowrap).

## License

[Boost Software License - Version 1.0](./LICENSE_1_0.txt)
