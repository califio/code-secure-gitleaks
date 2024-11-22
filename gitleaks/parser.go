package gitleaks

import (
	"encoding/json"
	"io"
)

func FromJson(reader io.Reader) ([]SecretFinding, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var secrets []SecretFinding
	err = json.Unmarshal(data, &secrets)
	if err != nil {
		return nil, err
	}
	return secrets, nil
}
