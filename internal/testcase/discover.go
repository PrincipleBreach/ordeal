package testcase

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Suffix is the required extension for Ordeal suite files.
const Suffix = ".test.yml"

// Discover expands paths (files or directories) into loaded suites. Directories
// are walked recursively for *.test.yml files. Results are sorted by path for
// deterministic output.
func Discover(paths []string) ([]*Suite, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			err := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.IsDir() && strings.HasSuffix(path, Suffix) {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			continue
		}
		files = append(files, p)
	}
	sort.Strings(files)

	suites := make([]*Suite, 0, len(files))
	for _, f := range files {
		s, err := Load(f)
		if err != nil {
			return nil, err
		}
		suites = append(suites, s)
	}
	return suites, nil
}
