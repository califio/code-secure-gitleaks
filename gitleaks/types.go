package gitleaks

type SecretFinding struct {
	Description string        `json:"Description"`
	StartLine   int           `json:"StartLine"`
	EndLine     int           `json:"EndLine"`
	StartColumn int           `json:"StartColumn"`
	EndColumn   int           `json:"EndColumn"`
	Match       string        `json:"Match"`
	Secret      string        `json:"Secret"`
	File        string        `json:"File"`
	SymlinkFile string        `json:"SymlinkFile"`
	Commit      string        `json:"Commit"`
	Entropy     float64       `json:"Entropy"`
	Author      string        `json:"Author"`
	Email       string        `json:"Email"`
	Date        string        `json:"Date"`
	Message     string        `json:"Message"`
	Tags        []interface{} `json:"Tags"`
	RuleID      string        `json:"RuleID"`
	Fingerprint string        `json:"Fingerprint"`
}
