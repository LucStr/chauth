package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/LucStr/chauth/internal/chconfig"
	"github.com/LucStr/chauth/internal/rbac"
)

// lint checks access rules offline: it reads only the config file and the YAML, never the files
// the config points to, and makes no network calls. It returns the exit code.
func lint(args []string) int {
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	path := fs.String("config", "", "serve config; enables the instance, database, role, generated-role and read-only checks")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: chauth lint [--config <file>] <dir>")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	var cfg *chconfig.Config
	var instances, roles rbac.Instances
	foldUsers := true
	if *path != "" {
		var err error
		if cfg, err = chconfig.Load(*path); err != nil {
			fmt.Fprintln(os.Stderr, *path+":", err)
			return 1
		}
		instances, roles = cfg.Databases(), cfg.Roles()
		foldUsers = cfg.OIDC.FoldUsername()
	}
	files, err := rbac.ReadDir(fs.Arg(0))
	if err == nil {
		_, err = os.Stat(fs.Arg(0))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	res, errs := rbac.ClickHouse.Parse(files)
	if len(errs) == 0 {
		_, errs = rbac.ClickHouse.Compile(res, instances, roles)
	}
	if len(errs) == 0 && cfg != nil {
		errs = cfg.CheckReadOnly(res)
	}
	for _, e := range errs {
		fmt.Println(e)
	}
	for _, w := range res.Warnings(foldUsers) {
		fmt.Println(w)
	}
	if len(errs) > 0 {
		return 1
	}
	fmt.Printf("ok: %d ChRole, %d ChRoleBinding in %d files\n", len(res.Roles), len(res.Bindings), len(files))
	return 0
}
