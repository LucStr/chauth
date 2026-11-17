package connect

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	serviceLabel       = "dev.chauth.connect"
	unitName           = "chauth-connect.service"
	serviceDescription = "chauth connect: local ClickHouse access through chauth"
)

// ServiceCommand runs `chauth service install|uninstall [--config file]`, which installs `chauth
// connect` as a launchd agent on macOS or a systemd user unit on Linux; configPath resolves --config.
func ServiceCommand(args []string, configPath func(string) string) error {
	if len(args) == 0 {
		return errors.New("usage: chauth service install|uninstall [--config file]")
	}
	fs := flag.NewFlagSet("service "+args[0], flag.ExitOnError)
	path := fs.String("config", "", "connect.yaml the service uses")
	_ = fs.Parse(args[1:])
	cfg, err := filepath.Abs(configPath(*path))
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	switch runtime.GOOS + " " + args[0] {
	case "darwin install":
		plist := filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist")
		logFile := filepath.Join(home, "Library", "Logs", "chauth-connect.log")
		if err := writeFile(plist, launchdPlist(exe, cfg, logFile)); err != nil {
			return err
		}
		domain := "gui/" + strconv.Itoa(os.Getuid())
		_ = exec.Command("launchctl", "bootout", domain+"/"+serviceLabel).Run()
		if err := run("launchctl", "bootstrap", domain, plist); err != nil {
			return err
		}
		fmt.Printf("installed %s; logs in %s\n", plist, logFile)
	case "darwin uninstall":
		_ = exec.Command("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+serviceLabel).Run()
		return removeFile(filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist"))
	case "linux install":
		unit := filepath.Join(home, ".config", "systemd", "user", unitName)
		if err := writeFile(unit, systemdUnit(exe, cfg)); err != nil {
			return err
		}
		if err := run("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		if err := run("systemctl", "--user", "enable", "--now", unitName); err != nil {
			return err
		}
		fmt.Printf("installed %s; logs: journalctl --user -u chauth-connect\n", unit)
	case "linux uninstall":
		_ = exec.Command("systemctl", "--user", "disable", "--now", unitName).Run()
		if err := removeFile(filepath.Join(home, ".config", "systemd", "user", unitName)); err != nil {
			return err
		}
		return run("systemctl", "--user", "daemon-reload")
	default:
		return fmt.Errorf("chauth service %s is not supported on %s", args[0], runtime.GOOS)
	}
	return nil
}

func launchdPlist(exe, cfg, logFile string) string {
	esc := func(s string) string {
		return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + serviceLabel + `</string>
  <key>ProgramArguments</key>
  <array><string>` + esc(exe) + `</string><string>connect</string><string>--config</string><string>` + esc(cfg) + `</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>` + esc(logFile) + `</string>
</dict>
</plist>
`
}

func systemdUnit(exe, cfg string) string {
	return `[Unit]
Description=` + serviceDescription + `

[Service]
ExecStart=` + strconv.Quote(exe) + ` connect --config ` + strconv.Quote(cfg) + `
Restart=on-failure

[Install]
WantedBy=default.target
`
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
