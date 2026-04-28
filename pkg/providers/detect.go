package providers

import (
	"fmt"
	"os/exec"
)

// Detect looks up the registered provider by name and resolves its binary
// in PATH, returning the absolute path of the first matching BinName.
// Returns an error if the provider is not registered or no candidate binary
// is found.
func Detect(name string) (string, error) {
	spec, ok := Lookup(name)
	if !ok {
		return "", fmt.Errorf("provider %q: not registered", name)
	}
	for _, bn := range spec.BinNames {
		if bin, err := exec.LookPath(bn); err == nil {
			return bin, nil
		}
	}
	return "", fmt.Errorf("provider %q: none of %v found in PATH", spec.Name, spec.BinNames)
}
