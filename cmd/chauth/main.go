// Command chauth is a ClickHouse proxy that accepts a short-lived OIDC token as the password and
// connects as a temporary user with exactly the holder's roles.
package main

import (
	"fmt"
	"os"
)

var version = "dev"

const usage = `chauth: ClickHouse access with short-lived OIDC tokens

Usage:
  chauth serve --config <file>          run the proxy (native and HTTPS)
  chauth lint [--config <file>] <dir>   check the ChRole / ChRoleBinding YAML in <dir>
  chauth connect [--config <file>]      serve localhost for ClickHouse clients: database <env>/<db>
  chauth ls [env]                       list the databases and roles you can reach and your level
  chauth login <env> | logout <env>     browser login now / forget the stored login
  chauth service install | uninstall    run chauth connect at login (launchd / systemd --user)
  chauth version                        print the version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "lint":
		os.Exit(lint(os.Args[2:]))
	case "connect":
		err = connectCmd(os.Args[2:])
	case "ls":
		err = lsCmd(os.Args[2:])
	case "login", "logout":
		err = loginCmd(os.Args[2:], os.Args[1] == "logout")
	case "service":
		err = serviceCmd(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "chauth:", err)
		os.Exit(1)
	}
}
