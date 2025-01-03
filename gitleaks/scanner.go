package gitleaks

import (
	"bufio"
	"fmt"
	"github.com/califio/code-secure-analyzer"
	"github.com/califio/code-secure-analyzer/logger"
	"io"
	"os"
	"os/exec"
)

type Scanner struct {
	Output      string
	ProjectPath string
}

func (scanner *Scanner) Type() analyzer.ScannerType {
	return analyzer.ScannerTypeSecretDetection
}

func (scanner *Scanner) Name() string {
	return "gitleaks"
}

func (scanner *Scanner) Scan() (*analyzer.FindingResult, error) {
	args := []string{
		"dir", scanner.ProjectPath,
		"--ignore-gitleaks-allow",
		"--exit-code", "0",
		"--report-format", "json",
		"--report-path", scanner.Output,
	}
	cmd := exec.Command("gitleaks", args...)
	logger.Info(cmd.String())
	cmd.Env = os.Environ()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	err := cmd.Start()
	if err != nil {
		return nil, err
	}
	go printStdout(stdout)
	go printStdout(stderr)
	err = cmd.Wait()
	if err != nil {
		return nil, err
	}
	reader, err := os.Open(scanner.Output)
	secrets, err := FromJson(reader)
	if err != nil {
		return nil, err
	}
	var result analyzer.FindingResult
	for _, secret := range secrets {
		result.Findings = append(result.Findings, analyzer.Finding{
			RuleID:         secret.RuleID,
			Identity:       secret.Fingerprint,
			Name:           fmt.Sprintf("Secret detected at %s:%d", secret.File, secret.StartLine),
			Description:    secret.Description,
			Category:       "Hardcode Secret",
			Recommendation: "",
			Severity:       analyzer.SeverityHigh,
			Location: &analyzer.FindingLocation{
				Path:        secret.File,
				Snippet:     secret.Match,
				StartLine:   secret.StartLine,
				EndLine:     secret.EndLine,
				StartColumn: secret.StartColumn,
				EndColumn:   secret.EndColumn,
			},
			Metadata: nil,
		})
	}
	return &result, nil
}

func printStdout(stdout io.ReadCloser) {
	reader := bufio.NewReader(stdout)
	line, _, err := reader.ReadLine()
	for {
		if err != nil || line == nil {
			break
		}
		logger.Println(string(line))
		line, _, err = reader.ReadLine()
	}
}
