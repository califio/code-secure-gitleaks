package main

import (
	"github.com/alecthomas/kong"
	"gitlab.com/code-secure/analyzer"
	"gitleaks/gitleaks"
)

type RunCmd struct {
	Output      string `help:"Output result" env:"GITLEAKS_OUTPUT" default:"gitleaks.json"`
	ProjectPath string `help:"Project path" env:"PROJECT_PATH" default:"."`
}

func (r *RunCmd) Run() error {
	secretAnalyzer := analyzer.NewFindingAnalyzer()
	// register scanner
	secretAnalyzer.RegisterScanner(&gitleaks.Scanner{
		Output:      r.Output,
		ProjectPath: r.ProjectPath,
	})
	secretAnalyzer.Run()
	return nil
}

var cli struct {
	Run RunCmd `cmd:"run" help:"gitleaks scan secrets"`
}

func main() {
	ctx := kong.Parse(&cli, kong.Name("analyzer"), kong.UsageOnError())
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
