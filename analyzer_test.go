package main

import (
	"fmt"
	"github.com/califio/code-secure-analyzer"
	"gitleaks/gitleaks"
	"os"
	"testing"
)

func initEnv() {
	os.Setenv("GITLAB_TOKEN", "change_me")
	os.Setenv("CI_SERVER_URL", "https://gitlab.com")
	//os.Setenv("CI_MERGE_REQUEST_IID", "18")
	os.Setenv("CI_PROJECT_ID", "50471841")
	os.Setenv("CI_PROJECT_URL", "https://gitlab.com/0xduo/vulnado2")
	os.Setenv("CI_PROJECT_NAME", "vulnado2")
	os.Setenv("CI_PROJECT_NAMESPACE", "0xduo")
	os.Setenv("CI_COMMIT_TITLE", "Commit Test2")
	os.Setenv("CI_COMMIT_BRANCH", "main")
	os.Setenv("CI_DEFAULT_BRANCH", "main")
	os.Setenv("CI_JOB_URL", "https://gitlab.com/0xduo/vulnado/-/jobs/8241092355")
	os.Setenv("CI_COMMIT_SHA", "891832b2fdecb72c444af1a6676eba6eb40435ab")
	os.Setenv("CODE_SECURE_TOKEN", "5b615904c5be41cc8af813ddee581432c818f6d9cb01475aa0ff6172c73edeb7")
	os.Setenv("CODE_SECURE_URL", "http://localhost:5272")
}

func TestParseResult(t *testing.T) {
	reader, err := os.Open("testdata/gitleaks.json")
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := gitleaks.FromJson(reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		fmt.Println(secret.File)
		fmt.Println(secret.Secret)
		fmt.Println("---")
	}
}

func TestScanAnalyzer(t *testing.T) {
	initEnv()
	newAnalyzer := analyzer.NewFindingAnalyzer()
	// register semgrep
	newAnalyzer.RegisterScanner(&gitleaks.Scanner{
		Output:      "gitleaks.json",
		ProjectPath: "../../vulnado",
	})
	// run
	newAnalyzer.Run()
}
