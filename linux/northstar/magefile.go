//go:build mage

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"
)

const (
	binaryName = "northstar"
	buildDir   = "bin"
	uiDir      = "ui"
	protoDir   = "proto"
)

var Default = Build

func Build() {
	mg.SerialDeps(UI.Build, Server.Build)
}

func Generate() error {

	if err := os.MkdirAll(filepath.Join(uiDir, "dist"), 0755); err != nil {
		return err
	}
	placeholder := filepath.Join(uiDir, "dist", "index.html")
	if _, err := os.Stat(placeholder); os.IsNotExist(err) {
		_ = os.WriteFile(placeholder, []byte("<html></html>"), 0644)
	}

	inputs := []string{
		filepath.Join(protoDir, "northstar.proto"),
		"buf.yaml",
		"buf.gen.yaml",
	}
	outputs := []string{
		filepath.Join(protoDir, "northstar.pb.go"),
		filepath.Join(protoDir, "northstarconnect", "northstar.connect.go"),
		filepath.Join(uiDir, "src", "gen", "northstar_pb.ts"),
		filepath.Join(uiDir, "src", "gen", "northstar_connect.ts"),
	}

	anyMissing := false
	for _, out := range outputs {
		if _, err := os.Stat(out); os.IsNotExist(err) {
			anyMissing = true
			break
		}
	}

	changed, err := target.Dir(outputs[0], inputs...)
	if err == nil && !changed && !anyMissing {
		return nil
	}

	fmt.Println("Generating code from proto...")
	return sh.RunV("buf", "generate")
}

func Clean() error {
	fmt.Println("Cleaning...")

	paths := []string{
		buildDir,
		filepath.Join(uiDir, "dist"),
		filepath.Join(protoDir, "northstar.pb.go"),
		filepath.Join(protoDir, "northstarconnect"),
		filepath.Join(uiDir, "src", "gen", "northstar_pb.ts"),
		filepath.Join(uiDir, "src", "gen", "northstar_connect.ts"),
	}

	for _, p := range paths {
		if err := os.RemoveAll(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func Fmt() {
	mg.SerialDeps(Server.Fmt, UI.Fmt, Proto.Fmt)
}

func Check() {
	mg.SerialDeps(Server.Check, UI.Check, Proto.Check)
}

type UI mg.Namespace

func (UI) Build() error {
	mg.Deps(Generate)

	distIndex := filepath.Join(uiDir, "dist", "index.html")

	changed, err := target.Dir(distIndex,
		filepath.Join(uiDir, "src"),
		filepath.Join(uiDir, "package.json"),
		filepath.Join(uiDir, "vite.config.ts"),
	)

	if err == nil && !changed {
		return nil
	}

	fmt.Println("Building UI...")
	return inDir(uiDir, func() error {
		if err := sh.RunV("npm", "install"); err != nil {
			return err
		}
		return sh.RunV("npm", "run", "build")
	})
}

func (UI) Dev() error {
	return inDir(uiDir, func() error {
		return sh.RunV("npm", "run", "dev")
	})
}

func (UI) Fmt() error {
	fmt.Println("Formatting UI code...")
	return inDir(uiDir, func() error {
		return sh.RunV("npx", "prettier", "--write", "src/**/*.{ts,tsx,css}")
	})
}

func (UI) Check() error {
	fmt.Println("Checking UI formatting...")
	return inDir(uiDir, func() error {
		return sh.RunV("npx", "prettier", "--check", "src/**/*.{ts,tsx,css}")
	})
}

type Server mg.Namespace

func (Server) Build() error {
	mg.Deps(Generate)

	binExt := ""
	if runtime.GOOS == "windows" {
		binExt = ".exe"
	}
	binaryPath := filepath.Join(buildDir, binaryName+binExt)

	changed, err := target.Dir(binaryPath,
		"pkg",
		"proto",
		"main.go",
		filepath.Join(uiDir, "dist", "index.html"),
	)

	if err == nil && !changed {
		return nil
	}

	fmt.Println("Building Go server...")
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		return err
	}

	return sh.RunV("go", "build", "-o", binaryPath, ".")
}

func (Server) Dev() error {
	mg.Deps(Generate)
	return sh.RunV("go", "run", ".", "-dev")
}

func (Server) Fmt() error {
	fmt.Println("Formatting Go code...")
	return sh.RunV("go", "fmt", "./...")
}

func (Server) Check() error {
	fmt.Println("Checking Go formatting...")
	out, err := sh.Output("gofmt", "-l", ".")
	if err != nil {
		return err
	}
	if out != "" {
		fmt.Printf("The following files are not formatted:\n%s\n", out)
		return fmt.Errorf("files not formatted")
	}
	return nil
}

type Proto mg.Namespace

func (Proto) Fmt() error {
	fmt.Println("Formatting protobuf files...")
	return sh.RunV("buf", "format", "-w", protoDir)
}

func (Proto) Check() error {
	fmt.Println("Checking protobuf formatting...")
	out, err := sh.Output("buf", "format", "-d", protoDir)
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) != "" {
		fmt.Printf("The following protobuf files are not formatted:\n%s\n", out)
		return fmt.Errorf("proto files not formatted")
	}
	return nil
}

func gitFiles(patterns ...string) ([]string, error) {
	args := append([]string{"ls-files"}, patterns...)
	out, err := sh.Output("git", args...)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(out), "\n"), nil
}

func inDir(dir string, fn func() error) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := os.Chdir(dir); err != nil {
		return err
	}
	defer os.Chdir(cwd)
	return fn()
}
