package chwire

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestHello(t *testing.T) {
	hello := Hello{ClientName: "ClickHouse client", Major: 26, Minor: 10, Revision: 54479, Database: "prod/core", User: UserJWT, Password: "eyJ.token"}
	var buf bytes.Buffer
	if _, err := hello.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	encoded := buf.Bytes()
	addendum := []byte{0, 'q'}
	tests := []struct {
		name  string
		input []byte
		max   int
		want  Hello
		err   error
		rest  []byte
	}{
		{"round trip leaves the next packet unread", append(append([]byte{}, encoded...), addendum...), DefaultMaxHello, hello, nil, addendum},
		{"exactly at the cap", encoded, len(encoded), hello, nil, nil},
		{"one byte over the cap", encoded, len(encoded) - 1, Hello{}, ErrTooLarge, nil},
		{"huge declared password is refused before allocation", append(binary.AppendUvarint([]byte{0, 0, 0, 0, 0, 0, 0}, 1<<40), 'x'), DefaultMaxHello, Hello{}, ErrTooLarge, nil},
		{"truncated", encoded[:len(encoded)-3], DefaultMaxHello, Hello{}, io.ErrUnexpectedEOF, nil},
		{"empty", nil, DefaultMaxHello, Hello{}, io.ErrUnexpectedEOF, nil},
		{"query before hello", append([]byte{1}, encoded[1:]...), DefaultMaxHello, Hello{}, ErrNotHello, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bufio.NewReader(bytes.NewReader(tt.input))
			got, err := ReadHello(r, tt.max)
			if !errors.Is(err, tt.err) {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
			if got != tt.want {
				t.Fatalf("hello = %+v, want %+v", got, tt.want)
			}
			if tt.err == nil {
				if rest, _ := io.ReadAll(r); !bytes.Equal(rest, tt.rest) {
					t.Fatalf("left in the reader: %v, want %v", rest, tt.rest)
				}
			}
		})
	}
}

func TestException(t *testing.T) {
	var written bytes.Buffer
	if err := WriteException(&written, 516, "DB::Exception", "token rejected"); err != nil {
		t.Fatal(err)
	}
	nested := []byte{ServerException}
	for _, e := range []struct {
		code      uint32
		name, msg string
		more      byte
	}{{81, "DB::Exception", "outer", 1}, {60, "DB::Exception", "inner", 0}} {
		nested = binary.LittleEndian.AppendUint32(nested, e.code)
		nested = appendString(appendString(appendString(nested, e.name), e.msg), "stack")
		nested = append(nested, e.more)
	}
	tests := []struct {
		name  string
		input []byte
		peek  uint64
		code  int32
		msg   string
		inner string
		err   string
	}{
		{"written exception decodes", written.Bytes(), ServerException, 516, "token rejected", "", ""},
		{"nested chain", nested, ServerException, 81, "outer", "inner", ""},
		{"truncated", written.Bytes()[:6], ServerException, 0, "", "", "unexpected EOF"},
		{"server hello is not an exception", []byte{ServerHello, 3, 'a', 'b', 'c'}, ServerHello, 0, "", "", "is not an Exception"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bufio.NewReader(bytes.NewReader(tt.input))
			if typ, err := PeekServerPacket(r); err != nil || typ != tt.peek {
				t.Fatalf("peek = %d, %v; want %d", typ, err, tt.peek)
			}
			if r.Buffered() != len(tt.input) {
				t.Fatal("peek consumed input")
			}
			e, err := ReadException(r, DefaultMaxHello)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil || e.Code != tt.code || e.Message != tt.msg {
				t.Fatalf("exception %+v, err %v", e, err)
			}
			if inner := ""; e.Nested != nil {
				inner = e.Nested.Message
				if inner != tt.inner {
					t.Fatalf("nested = %q, want %q", inner, tt.inner)
				}
			} else if tt.inner != "" {
				t.Fatal("nested exception missing")
			}
		})
	}
}

func TestRefusedUser(t *testing.T) {
	for user, want := range map[string]bool{UserInterserverSecret: true, UserSSHKey: true, UserJWT: false, "": false, "alice": false, "INTERSERVER SECRET": false} {
		if got := RefusedUser(user); got != want {
			t.Errorf("RefusedUser(%q) = %v, want %v", user, got, want)
		}
	}
}
