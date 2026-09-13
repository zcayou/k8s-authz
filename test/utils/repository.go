package utils

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

var repositoryRoot = sync.OnceValues(func() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", errors.New("go.mod not found above the working directory")
		}
		directory = parent
	}
})

// RepositoryPath joins elements to the repository root, which it finds from
// the test binary's working directory.
func RepositoryPath(elements ...string) (string, error) {
	root, err := repositoryRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{root}, elements...)...), nil
}
