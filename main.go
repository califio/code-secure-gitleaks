package main

import (
	"github.com/alecthomas/kong"
	"github.com/califio/code-secure-analyzer"
	"gitleaks/gitleaks"
)

type RunCmd struct {
	Output      string `help:"Output result" env:"GITLEAKS_OUTPUT" default:"gitleaks.json"`
	ProjectPath string `help:"Project path" env:"PROJECT_PATH" default:"."`
}

func (r *RunCmd) Run() error {
	secretAnalyzer := analyzer.NewSastAnalyzer(analyzer.SastAnalyzerOption{
		ProjectPath: r.ProjectPath,
		Scanner: &gitleaks.Scanner{
			Output:      r.Output,
			ProjectPath: r.ProjectPath,
		},
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
