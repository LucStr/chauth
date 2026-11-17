// Package chwire reads and writes the few ClickHouse native-protocol packets chauth looks at: the
// client Hello, which carries the token, and the server's first reply. Everything after the Hello
// is copied as bytes and never decoded.
package chwire

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Packet types; the client and server number their packets independently.
const (
	ClientHello     = 0
	ServerHello     = 0
	ServerException = 2
)

// User markers a client puts in the Hello's user field instead of a name.
const (
	UserInterserverSecret = " INTERSERVER SECRET "
	UserSSHKey            = " SSH KEY AUTHENTICATION "
	// UserJWT carries the token in the password field.
	UserJWT = " JWT AUTHENTICATION "
)

// RefusedUser reports a user marker that would authenticate by something other than the token.
func RefusedUser(user string) bool {
	return user == UserInterserverSecret || user == UserSSHKey
}

// Exception codes chauth sends on both sides, always named ExceptionName: another name makes
// clickhouse-client print it twice. Never 516: on it the interactive client prompts for a password.
const (
	CodeUnknownDatabase  = 81
	CodeUnexpectedPacket = 101
	CodeTooManyQueries   = 202
	CodeNetworkError     = 210
	CodeAccessDenied     = 497
	// CodeAuthenticationFailed is what ClickHouse answers for a wrong password, unknown user or host.
	CodeAuthenticationFailed = 516
)

const ExceptionName = "DB::Exception"

var codeNames = map[int32]string{
	CodeUnknownDatabase:      "UNKNOWN_DATABASE",
	CodeUnexpectedPacket:     "UNEXPECTED_PACKET_FROM_CLIENT",
	CodeTooManyQueries:       "TOO_MANY_SIMULTANEOUS_QUERIES",
	CodeNetworkError:         "NETWORK_ERROR",
	CodeAccessDenied:         "ACCESS_DENIED",
	CodeAuthenticationFailed: "AUTHENTICATION_FAILED",
}

// CodeName is ClickHouse's name of code, as shown in parentheses after a message.
func CodeName(code int32) string { return codeNames[code] }

// DefaultMaxHello caps the bytes a client may send before it is authenticated.
const DefaultMaxHello = 64 << 10

var (
	ErrNotHello = errors.New("first packet is not a client Hello")
	ErrTooLarge = errors.New("packet exceeds the size limit")
)

// Hello is the first packet of a native connection.
type Hello struct {
	ClientName               string
	Major, Minor, Revision   uint64
	Database, User, Password string
}

// ReadHello reads exactly one client Hello and nothing after it; the client's following packets
// stay in r. It fails with ErrNotHello, ErrTooLarge or io.ErrUnexpectedEOF.
func ReadHello(r *bufio.Reader, maxBytes int) (Hello, error) {
	d := &decoder{r: r, left: maxBytes}
	typ, err := d.uvarint()
	if err != nil {
		return Hello{}, err
	}
	if typ != ClientHello {
		return Hello{}, ErrNotHello
	}
	var h Hello
	h.ClientName = d.string()
	h.Major = d.mustUvarint()
	h.Minor = d.mustUvarint()
	h.Revision = d.mustUvarint()
	h.Database = d.string()
	h.User = d.string()
	h.Password = d.string()
	if d.err != nil {
		return Hello{}, d.err
	}
	return h, nil
}

// WriteTo encodes h as a client Hello.
func (h Hello) WriteTo(w io.Writer) (int64, error) {
	var b []byte
	b = binary.AppendUvarint(b, ClientHello)
	b = appendString(b, h.ClientName)
	b = binary.AppendUvarint(b, h.Major)
	b = binary.AppendUvarint(b, h.Minor)
	b = binary.AppendUvarint(b, h.Revision)
	b = appendString(b, h.Database)
	b = appendString(b, h.User)
	b = appendString(b, h.Password)
	n, err := w.Write(b)
	return int64(n), err
}

// Exception is a server Exception packet; Nested is the next one in its chain.
type Exception struct {
	Code       int32
	Name       string
	Message    string
	StackTrace string
	Nested     *Exception
}

func (e *Exception) Error() string { return fmt.Sprintf("code %d: %s", e.Code, e.Message) }

// WriteException sends one Exception packet named ExceptionName, without a stack trace or nested exception.
func WriteException(w io.Writer, code int32, message string) error {
	var b []byte
	b = binary.AppendUvarint(b, ServerException)
	b = binary.LittleEndian.AppendUint32(b, uint32(code))
	b = appendString(b, ExceptionName)
	b = appendString(b, message)
	b = appendString(b, "")
	b = append(b, 0)
	_, err := w.Write(b)
	return err
}

// PeekServerPacket returns the type of the server's next packet without consuming it.
func PeekServerPacket(r *bufio.Reader) (uint64, error) {
	b, err := r.Peek(1)
	if err != nil {
		return 0, err
	}
	if b[0] >= 0x80 {
		return 0, fmt.Errorf("unexpected server packet type byte 0x%x", b[0])
	}
	return uint64(b[0]), nil
}

// ReadException consumes one Exception packet and its nested chain, maxBytes in total.
func ReadException(r *bufio.Reader, maxBytes int) (*Exception, error) {
	d := &decoder{r: r, left: maxBytes}
	typ, err := d.uvarint()
	if err != nil {
		return nil, err
	}
	if typ != ServerException {
		return nil, fmt.Errorf("server packet %d is not an Exception", typ)
	}
	var first, last *Exception
	for {
		e := &Exception{Code: int32(d.uint32()), Name: d.string(), Message: d.string(), StackTrace: d.string()}
		nested := d.byte()
		if d.err != nil {
			return nil, d.err
		}
		if first == nil {
			first = e
		} else {
			last.Nested = e
		}
		last = e
		if nested == 0 {
			return first, nil
		}
	}
}

func appendString(b []byte, s string) []byte {
	return append(binary.AppendUvarint(b, uint64(len(s))), s...)
}

// decoder reads at most left bytes; the first error sticks.
type decoder struct {
	r    *bufio.Reader
	left int
	err  error
}

func (d *decoder) fail(err error) {
	if d.err == nil {
		d.err = err
	}
}

func (d *decoder) byte() byte {
	if d.err != nil {
		return 0
	}
	if d.left <= 0 {
		d.fail(ErrTooLarge)
		return 0
	}
	c, err := d.r.ReadByte()
	if err != nil {
		d.fail(unexpected(err))
		return 0
	}
	d.left--
	return c
}

func (d *decoder) uvarint() (uint64, error) {
	var x uint64
	for i := 0; i < binary.MaxVarintLen64; i++ {
		c := d.byte()
		if d.err != nil {
			return 0, d.err
		}
		x |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return x, nil
		}
	}
	d.fail(errors.New("varint overflows 64 bits"))
	return 0, d.err
}

func (d *decoder) mustUvarint() uint64 {
	if d.err != nil {
		return 0
	}
	x, _ := d.uvarint()
	return x
}

func (d *decoder) uint32() uint32 {
	var b [4]byte
	for i := range b {
		b[i] = d.byte()
	}
	return binary.LittleEndian.Uint32(b[:])
}

func (d *decoder) string() string {
	n := d.mustUvarint()
	if d.err != nil {
		return ""
	}
	if n > uint64(d.left) {
		d.fail(ErrTooLarge)
		return ""
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(d.r, b); err != nil {
		d.fail(unexpected(err))
		return ""
	}
	d.left -= int(n)
	return string(b)
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
