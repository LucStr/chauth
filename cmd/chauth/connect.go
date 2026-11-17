package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/LucStr/chauth/internal/chconnect"
	"github.com/LucStr/chauth/internal/connect"
)

const (
	defaultCallbackPort = 8250
	defaultListen       = "127.0.0.1:9000"
	defaultListenHTTP   = "127.0.0.1:8123"
)

// configPath picks connect.yaml: --config, then $CHAUTH_CONFIG, then the user config directory.
func configPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("CHAUTH_CONFIG"); env != "" {
		return env
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "chauth", "connect.yaml")
	}
	return "connect.yaml"
}

func newLog() *slog.Logger { return slog.New(slog.NewTextHandler(os.Stderr, nil)) }

// loadConnect reads and validates a chauth connect.yaml.
func loadConnect(path string) (*connect.File, error) {
	f, err := connect.LoadFile(path)
	if err != nil {
		return nil, err
	}
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

func connectCmd(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	path := fs.String("config", "", "connect.yaml (default $CHAUTH_CONFIG, else the user config directory)")
	listen := fs.String("listen", "", `local native address (default "`+defaultListen+`")`)
	listenHTTP := fs.String("listen-http", "", `local HTTP address (default "`+defaultListenHTTP+`")`)
	callbackPort := fs.Int("callback-port", defaultCallbackPort, "loopback port of the login redirect; 0 picks a free port")
	_ = fs.Parse(args)

	f, err := loadConnect(configPath(*path))
	if err != nil {
		return err
	}
	native, http := firstOf(*listen, f.Listen, defaultListen), firstOf(*listenHTTP, f.ListenHTTP, defaultListenHTTP)
	port := *callbackPort
	if f.CallbackPort != nil && !flagSet(fs, "callback-port") {
		port = *f.CallbackPort
	}
	return runConnect(context.Background(), f, native, http, port, newLog())
}

func runConnect(ctx context.Context, f *connect.File, native, http string, callbackPort int, log *slog.Logger) error {
	listeners, err := chconnect.Listeners(f, native, http)
	if err != nil {
		return err
	}
	c, err := newConnector(f, callbackPort, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return c.Run(ctx, listeners)
}

func newConnector(f *connect.File, callbackPort int, log *slog.Logger) (*chconnect.Connector, error) {
	envs, err := chconnect.BuildEnvs(f, chconnect.Options{
		Store: connect.Keychain{}, OpenBrowser: openBrowser, CallbackPort: callbackPort, Log: log,
	})
	if err != nil {
		return nil, err
	}
	return chconnect.New(envs, log), nil
}

func callbackPortOf(f *connect.File) int {
	if f.CallbackPort != nil {
		return *f.CallbackPort
	}
	return defaultCallbackPort
}

func lsCmd(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	path := fs.String("config", "", "connect.yaml")
	_ = fs.Parse(args)
	f, err := loadConnect(configPath(*path))
	if err != nil {
		return err
	}
	names := f.EnvNames()
	if fs.NArg() > 0 {
		if !slices.Contains(names, fs.Arg(0)) {
			return fmt.Errorf("no environment %s; environments: %s", fs.Arg(0), strings.Join(names, ", "))
		}
		names = []string{fs.Arg(0)}
	}
	return runLs(context.Background(), f, names, newLog())
}

func runLs(ctx context.Context, f *connect.File, names []string, log *slog.Logger) error {
	c, err := newConnector(f, callbackPortOf(f), log)
	if err != nil {
		return err
	}
	return c.PrintAccess(ctx, os.Stdout, os.Stderr, names)
}

// loginCmd runs `chauth login <env>`: a fresh browser login, then what it reaches; `logout <env>`
// forgets the stored refresh token.
func loginCmd(args []string, logout bool) error {
	verb := "login"
	if logout {
		verb = "logout"
	}
	fs := flag.NewFlagSet(verb, flag.ExitOnError)
	path := fs.String("config", "", "connect.yaml")
	_ = fs.Parse(args)
	f, err := loadConnect(configPath(*path))
	if err != nil {
		return err
	}
	if fs.NArg() != 1 || f.Environments[fs.Arg(0)] == nil {
		return fmt.Errorf("usage: chauth %s <env>; environments: %s", verb, strings.Join(f.EnvNames(), ", "))
	}
	name := fs.Arg(0)
	t := f.Environments[name].Token
	if t.File != "" {
		return fmt.Errorf("environment %s reads its token from a file; there is nothing to %s", name, verb)
	}
	if logout {
		return connect.Keychain{}.Delete(connect.KeychainKey(name, t))
	}
	log := newLog()
	c, err := newConnector(f, callbackPortOf(f), log)
	if err != nil {
		return err
	}
	e, _ := c.Env(name)
	ctx := context.Background()
	if err := e.Tokens.(*connect.Connector).Login(ctx); err != nil {
		return err
	}
	return c.PrintAccess(ctx, os.Stdout, os.Stderr, []string{name})
}

func serviceCmd(args []string) error {
	return connect.ServiceCommand(args, configPath)
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}
