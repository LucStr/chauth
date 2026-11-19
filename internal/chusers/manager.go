// Package chusers creates, reuses and drops chauth's temp users on one ClickHouse instance. A temp
// user belongs to the process that created it; a sweep drops expired temp users of any process.
package chusers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/LucStr/chauth/internal/chconfig"
	"github.com/LucStr/chauth/internal/chwire"
	"github.com/LucStr/chauth/internal/rbac"
)

// Key decides which connections share a temp user: all fields must match.
type Key struct {
	Subject string
	// Email goes into the user's log_comment.
	Email string
	Level rbac.Level
	// Roles are the upstream roles the user is granted.
	Roles []string
	// Tables are privileges granted to the user directly; an empty Table means the whole database.
	Tables []rbac.TableGrant
}

func (k Key) id() string {
	roles := slices.Clone(k.Roles)
	slices.Sort(roles)
	var b strings.Builder
	b.WriteString(k.Subject + "\x00" + k.Email + "\x00" + k.Level.String() + "\x00" + strings.Join(roles, ","))
	for _, t := range k.Tables {
		b.WriteString("\x00" + t.Database + "\x01" + t.Table + "\x01" + t.Verb)
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}

// grantTables is one GRANT statement for every table privilege of k, or "" without any.
func grantTables(k Key, user string) string {
	parts := make([]string, len(k.Tables))
	for i, t := range k.Tables {
		on := Ident(t.Database) + ".*"
		if t.Table != "" {
			on = Ident(t.Database) + "." + Ident(t.Table)
		}
		parts[i] = t.Privilege() + " ON " + on
	}
	if len(parts) == 0 {
		return ""
	}
	return "GRANT " + strings.Join(parts, ", ") + " TO " + Ident(user)
}

// Options are the lifetimes from the serve config's limits.
type Options struct {
	// LeaseDuration is how long one user is handed out to new connections.
	LeaseDuration time.Duration
	// MaxConnectionAge is the longest a connection may use a user after it was handed out.
	MaxConnectionAge time.Duration
	// IdleTTL is how long a user without connections is kept for reuse.
	IdleTTL time.Duration
	// MaxRefs is how many connections share one user before another is created.
	MaxRefs int
	// ProbeTimeout bounds the retries of the first login of a new user.
	ProbeTimeout time.Duration
	Log          *slog.Logger
	// Password generates temp-user passwords; nil is the built-in generator.
	Password func() string
}

// validGrace is added to a user's longest possible use for its VALID UNTIL.
const validGrace = 5 * time.Minute

type Manager struct {
	admin  *Admin
	prefix string
	hosts  []string
	opts   Options
	nonce  string

	mu      sync.Mutex
	current map[string]*entry // key id → the user new connections get
	byName  map[string]*entry // every user this process created and has not dropped
	retry   map[string]bool   // users whose drop failed
	closed  bool

	created, dropped, dropFailed metric.Int64Counter
	live                         metric.Int64UpDownCounter
	selfTestRuns                 metric.Int64Counter
	selfTestOK, selfTestTime     metric.Int64Gauge
	instance                     metric.MeasurementOption
}

type entry struct {
	name, password, key  string
	selfTest             bool
	leaseEnd, validUntil time.Time
	refs                 int
	dropped              bool
	ready                chan struct{}
	err                  error
	idle                 *time.Timer
}

// Lease is one connection's use of a temp user; Release it exactly once when the connection ends.
type Lease struct {
	User, Password string
	Expires        time.Time
	release        func()
	once           sync.Once
}

func (l *Lease) Release() { l.once.Do(l.release) }

func NewManager(admin *Admin, in chconfig.Instance, opts Options) *Manager {
	if opts.MaxRefs <= 0 {
		opts.MaxRefs = 20
	}
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = 10 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Password == nil {
		opts.Password = password
	}
	meter := otel.Meter("github.com/LucStr/chauth/internal/chusers")
	created, _ := meter.Int64Counter("chauth.users.created", metric.WithDescription("Temp users created"))
	dropped, _ := meter.Int64Counter("chauth.users.dropped", metric.WithDescription("Temp users dropped"))
	failed, _ := meter.Int64Counter("chauth.users.drop_failed", metric.WithDescription("Temp users that could not be dropped"))
	live, _ := meter.Int64UpDownCounter("chauth.users.live", metric.WithDescription("Temp users this process holds"))
	runs, _ := meter.Int64Counter("chauth.selftest.runs", metric.WithDescription("Temp-user self-tests by result, pass or fail"))
	ok, _ := meter.Int64Gauge("chauth.selftest.ok", metric.WithDescription("1 when the last temp-user self-test passed, else 0"))
	at, _ := meter.Int64Gauge("chauth.selftest.time", metric.WithDescription("When the last temp-user self-test finished"), metric.WithUnit("s"))
	return &Manager{
		admin: admin, prefix: in.TempUserPrefix, hosts: in.TempUserHostIPs, opts: opts, nonce: randomName(6),
		current: map[string]*entry{}, byName: map[string]*entry{}, retry: map[string]bool{},
		created: created, dropped: dropped, dropFailed: failed, live: live,
		selfTestRuns: runs, selfTestOK: ok, selfTestTime: at, instance: metric.WithAttributes(attribute.String("chauth.instance", in.Name)),
	}
}

// Nonce identifies this process in the names of its users.
func (m *Manager) Nonce() string { return m.nonce }

// Acquire hands out a temp user for k, creating one when none can be reused. A new user has logged
// in once before it is handed out.
func (m *Manager) Acquire(ctx context.Context, k Key) (*Lease, error) {
	if err := checkKey(k); err != nil {
		return nil, err
	}
	id := k.id()
	now := time.Now()
	m.mu.Lock()
	e := m.current[id]
	creator := false
	if e == nil || e.refs >= m.opts.MaxRefs || !now.Before(e.leaseEnd) || failed(e) {
		e = &entry{
			name: m.userName(k.Subject), password: m.opts.Password(), key: id,
			leaseEnd: now.Add(m.opts.LeaseDuration), ready: make(chan struct{}),
		}
		e.validUntil = e.leaseEnd.Add(m.opts.MaxConnectionAge + validGrace)
		m.current[id] = e
		m.byName[e.name] = e
		creator = true
	}
	e.refs++
	if e.idle != nil {
		e.idle.Stop()
		e.idle = nil
	}
	m.mu.Unlock()

	var err error
	if creator {
		err = m.create(ctx, e, k)
		m.mu.Lock()
		e.err = err
		m.mu.Unlock()
		close(e.ready)
	} else {
		select {
		case <-e.ready:
			m.mu.Lock()
			err = e.err
			m.mu.Unlock()
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	if err != nil {
		m.release(e)
		return nil, err
	}
	return &Lease{User: e.name, Password: e.password, Expires: e.validUntil, release: func() { m.release(e) }}, nil
}

// failed reports a user whose creation finished with an error; m.mu must be held.
func failed(e *entry) bool {
	select {
	case <-e.ready:
		return e.err != nil
	default:
		return false
	}
}

func (m *Manager) release(e *entry) {
	m.mu.Lock()
	e.refs--
	if e.refs > 0 {
		m.mu.Unlock()
		return
	}
	done := false
	select {
	case <-e.ready:
		done = true
	default:
	}
	if done && e.err == nil && m.current[e.key] == e && time.Now().Before(e.leaseEnd) && !m.closed {
		e.idle = time.AfterFunc(m.opts.IdleTTL, func() { m.dropIdle(e) })
		m.mu.Unlock()
		return
	}
	m.forget(e)
	drop := done && e.err == nil && !e.dropped
	e.dropped = true
	m.mu.Unlock()
	if drop {
		m.drop(context.Background(), e.name)
	}
}

func (m *Manager) dropIdle(e *entry) {
	m.mu.Lock()
	if e.refs > 0 || m.byName[e.name] != e || e.dropped {
		m.mu.Unlock()
		return
	}
	m.forget(e)
	e.dropped = true
	m.mu.Unlock()
	m.drop(context.Background(), e.name)
}

// forget removes e from the maps; m.mu must be held.
func (m *Manager) forget(e *entry) {
	if m.byName[e.name] == e {
		delete(m.byName, e.name)
	}
	if m.current[e.key] == e {
		delete(m.current, e.key)
	}
}

func (m *Manager) create(ctx context.Context, e *entry, k Key) error {
	var b strings.Builder
	fmt.Fprintf(&b, "CREATE USER %s IDENTIFIED WITH sha256_password BY %s VALID UNTIL %s",
		Ident(e.name), Literal(e.password), Literal(e.validUntil.UTC().Format(time.DateTime)+" UTC"))
	if len(m.hosts) > 0 {
		hosts := make([]string, len(m.hosts))
		for i, h := range m.hosts {
			hosts[i] = "IP " + Literal(h)
		}
		b.WriteString(" HOST " + strings.Join(hosts, ", "))
	}
	b.WriteString(" SETTINGS log_comment = " + Literal(k.Email) + " CONST")
	if k.Level < rbac.Write {
		b.WriteString(", readonly = 2 CONST")
	}
	if err := m.admin.Exec(ctx, b.String()); err != nil {
		return &StepError{Step: "create temp user", Err: err}
	}
	if !e.selfTest {
		m.created.Add(ctx, 1)
		m.live.Add(ctx, 1)
	}
	var err error
	if len(k.Roles) > 0 {
		quoted := make([]string, len(k.Roles))
		for i, r := range k.Roles {
			quoted[i] = Ident(r)
		}
		if err = m.admin.Exec(ctx, "GRANT "+strings.Join(quoted, ", ")+" TO "+Ident(e.name)); err != nil {
			err = &StepError{Step: "grant roles to temp user", Err: err}
		}
	}
	if stmt := grantTables(k, e.name); err == nil && stmt != "" {
		if err = m.admin.Exec(ctx, stmt); err != nil {
			err = &StepError{Step: "grant tables to temp user", Err: err}
		}
	}
	if err == nil {
		if err = m.probe(ctx, e); err != nil {
			err = &StepError{Step: "first login of temp user", Err: err}
		}
	}
	if err != nil {
		_ = m.dropEntry(context.WithoutCancel(ctx), e)
	}
	return err
}

// dropEntry drops e; a self-test user is left out of the metrics and retries of people's users.
func (m *Manager) dropEntry(ctx context.Context, e *entry) error {
	if !e.selfTest {
		return m.drop(ctx, e.name)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return m.admin.Exec(ctx, "DROP USER IF EXISTS "+Ident(e.name))
}

// probe logs in as the new user until it works: on a cluster with several replicas the user may not
// have reached the replica that answers yet.
func (m *Manager) probe(ctx context.Context, e *entry) error {
	deadline := time.Now().Add(m.opts.ProbeTimeout)
	for wait := 20 * time.Millisecond; ; wait = min(2*wait, time.Second) {
		err := m.admin.Login(ctx, e.name, e.password)
		if err == nil || !isCode(err, chwire.CodeAuthenticationFailed) || time.Now().Add(wait).After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (m *Manager) drop(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := m.admin.Exec(ctx, "DROP USER IF EXISTS "+Ident(name)); err != nil {
		m.dropFailed.Add(ctx, 1)
		m.opts.Log.Error("temp user not dropped; retried on the next sweep", "temp_user", name, "error", err)
		m.mu.Lock()
		m.retry[name] = true
		m.mu.Unlock()
		return err
	}
	m.dropped.Add(ctx, 1)
	m.live.Add(ctx, -1)
	m.mu.Lock()
	delete(m.retry, name)
	m.mu.Unlock()
	return nil
}

// StepError is a failed step of creating, granting, logging in as or dropping a temp user.
type StepError struct {
	Step string
	Err  error
}

func (e *StepError) Error() string { return e.Step + ": " + e.Err.Error() }
func (e *StepError) Unwrap() error { return e.Err }

// SelfTest creates a temp user the way Acquire does, with roles and tables, logs in as it and drops
// it. The user is never handed out; one left by a crash expires within minutes and the sweep drops it.
func (m *Manager) SelfTest(ctx context.Context, roles []string, tables []rbac.TableGrant) error {
	k := Key{Subject: "selftest", Email: "chauth self-test", Level: rbac.Read, Roles: roles, Tables: tables}
	err := checkKey(k)
	if err == nil {
		e := &entry{name: m.selfTestName(), password: m.opts.Password(), selfTest: true}
		e.validUntil = time.Now().Add(m.opts.ProbeTimeout + validGrace)
		if err = m.create(ctx, e, k); err == nil {
			if derr := m.dropEntry(context.WithoutCancel(ctx), e); derr != nil {
				err = &StepError{Step: "drop temp user", Err: derr}
			}
		} else if se := (*StepError)(nil); errors.As(err, &se) && se.Step == "create temp user" {
			_ = m.dropEntry(context.WithoutCancel(ctx), e)
		}
	}
	ok, result := int64(0), "fail"
	if err == nil {
		ok, result = 1, "pass"
	}
	m.selfTestRuns.Add(ctx, 1, m.instance, metric.WithAttributes(attribute.String("result", result)))
	m.selfTestOK.Record(ctx, ok, m.instance)
	m.selfTestTime.Record(ctx, time.Now().Unix(), m.instance)
	return err
}

// Sweep drops temp users of any process whose VALID UNTIL has passed, and retries this process's
// failed drops. A user with no VALID UNTIL is never dropped.
func (m *Manager) Sweep(ctx context.Context) (int, error) {
	var expired []string
	now := time.Now().Unix()
	err := m.admin.Rows(ctx, "SELECT name, arrayMap(x -> toUnixTimestamp(x), valid_until) AS until FROM system.users WHERE startsWith(name, "+Literal(m.prefix)+")",
		func(line []byte) error {
			var row struct {
				Name  string  `json:"name"`
				Until []int64 `json:"until"`
			}
			if err := json.Unmarshal(line, &row); err != nil {
				return err
			}
			if len(row.Until) > 0 && !slices.ContainsFunc(row.Until, func(t int64) bool { return t == 0 || t > now }) {
				expired = append(expired, row.Name)
			}
			return nil
		})
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	for name := range m.retry {
		if !slices.Contains(expired, name) {
			expired = append(expired, name)
		}
	}
	m.mu.Unlock()
	n := 0
	for _, name := range expired {
		if !strings.HasPrefix(name, m.prefix) || !validName(name) {
			continue
		}
		m.mu.Lock()
		own := m.retry[name]
		if e := m.byName[name]; e != nil {
			m.forget(e)
			own = own || !e.dropped
			e.dropped = true
		}
		m.mu.Unlock()
		if own {
			m.drop(ctx, name)
		} else if err := m.admin.Exec(ctx, "DROP USER IF EXISTS "+Ident(name)); err != nil {
			m.opts.Log.Error("sweep: temp user not dropped", "temp_user", name, "error", err)
			continue
		} else {
			m.dropped.Add(ctx, 1)
		}
		n++
	}
	return n, nil
}

// Run sweeps every interval until ctx ends.
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n, err := m.Sweep(ctx); err != nil {
			m.opts.Log.Error("sweep temp users", "error", err)
		} else if n > 0 {
			m.opts.Log.Info("swept temp users", "dropped", n)
		}
	}
}

// Close drops every user this process created, in use or not; call it after the listeners closed.
func (m *Manager) Close(ctx context.Context) {
	m.mu.Lock()
	m.closed = true
	names := make([]string, 0, len(m.byName))
	for name, e := range m.byName {
		if e.idle != nil {
			e.idle.Stop()
		}
		select {
		case <-e.ready:
		default:
			continue // still being created: released after Close, it is dropped at once
		}
		if e.err == nil && !e.dropped {
			names = append(names, name)
		}
		e.dropped = true
		m.forget(e)
	}
	m.mu.Unlock()
	for _, name := range names {
		m.drop(ctx, name)
	}
}

var ErrBadKey = errors.New("temp user key rejected")

func checkKey(k Key) error {
	if k.Subject == "" || k.Email == "" {
		return fmt.Errorf("%w: subject and email are required", ErrBadKey)
	}
	if !utf8.ValidString(k.Email) || strings.ContainsFunc(k.Email, unicode.IsControl) {
		return fmt.Errorf("%w: email contains control characters", ErrBadKey)
	}
	if len(k.Roles) == 0 && len(k.Tables) == 0 {
		return fmt.Errorf("%w: no roles and no tables", ErrBadKey)
	}
	for _, t := range k.Tables {
		if t.Database == "" || t.Privilege() == "" {
			return fmt.Errorf("%w: table grant %+v", ErrBadKey, t)
		}
	}
	for _, r := range k.Roles {
		if !rbac.ValidUpstreamRole(r) {
			return fmt.Errorf("%w: role %q", ErrBadKey, r)
		}
	}
	return nil
}

// Ident quotes s as a ClickHouse identifier.
func Ident(s string) string {
	return "`" + strings.NewReplacer(`\`, `\\`, "`", "\\`").Replace(s) + "`"
}

// Literal quotes s as a ClickHouse string literal.
func Literal(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// userName is a person's temp user: short never starts with '_', so it cannot take selfTestName's shape.
func (m *Manager) userName(subject string) string {
	return m.prefix + short(subject) + "_" + m.nonce + randomName(6)
}

func (m *Manager) selfTestName() string { return m.prefix + "_selftest_" + m.nonce + randomName(6) }

func validName(name string) bool {
	return name != "" && !strings.ContainsFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_')
	})
}

// short is 8 characters of [a-z0-9] taken from sub, padded from its hash.
func short(sub string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(sub) {
		if b.Len() == 8 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	h := sha256.Sum256([]byte(sub))
	return (b.String() + hex.EncodeToString(h[:]))[:8]
}

var lowerBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func randomName(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return lowerBase32.EncodeToString(b)[:n]
}

// passwordClasses each give at least two characters of every password. It travels only in a SQL literal,
// HTTP Basic auth and the native Hello; never put it into a URL or a command line.
var passwordClasses = []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789", "!#%*+-=_"}

// password is 32 random characters with at least two of every class, in random positions.
func password() string {
	all := strings.Join(passwordClasses, "")
	b := make([]byte, 0, 32)
	for _, class := range passwordClasses {
		b = append(b, class[randomInt(len(class))], class[randomInt(len(class))])
	}
	for len(b) < cap(b) {
		b = append(b, all[randomInt(len(all))])
	}
	for i := len(b) - 1; i > 0; i-- {
		j := randomInt(i + 1)
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func randomInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}
