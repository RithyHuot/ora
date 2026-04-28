package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// fakeConn is a minimal net.Conn backed by a bytes.Buffer for Read tests.
type fakeConn struct {
	bytes.Buffer
}

func (f *fakeConn) Close() error                     { return nil }
func (f *fakeConn) LocalAddr() net.Addr              { return nil }
func (f *fakeConn) RemoteAddr() net.Addr             { return nil }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func TestBufferedConn_Read(t *testing.T) {
	cases := []struct {
		name       string
		head       []byte
		underlying string
		bufSize    int
		want       string
	}{
		{"empty head reads underlying", nil, "abc", 8, "abc"},
		{"head only", []byte("xyz"), "", 8, "xyz"},
		{"head then underlying", []byte("xy"), "z", 8, "xyz"},
		{"partial copy across multiple reads", []byte("hello"), "", 2, "hello"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &fakeConn{}
			inner.WriteString(tc.underlying)
			bc := &bufferedConn{Conn: inner, head: append([]byte(nil), tc.head...)}
			got, err := io.ReadAll(struct{ io.Reader }{bc})
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
