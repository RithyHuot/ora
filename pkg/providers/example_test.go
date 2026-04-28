package providers_test

import (
	"fmt"

	"github.com/rithyhuot/ora/pkg/providers"
)

func ExampleRegister() {
	name := "example-out-of-tree"
	defer providers.Unregister(name)

	err := providers.Register(providers.ProviderSpec{
		Name:     name,
		BinNames: []string{"example-cli"},
		AuthDirsRW: providers.AuthResolver(func(home string, _ map[string]string) []providers.AuthDirEntry {
			return []providers.AuthDirEntry{
				{Path: home + "/.example-cli", Kind: providers.AuthDirKindDir},
			}
		}),
		OwnEnvKeys: []string{"EXAMPLE_API_KEY"},
		ProbeHost:  "api.example.com",
	})
	if err != nil {
		// Register refuses to overwrite a builtin provider.
		fmt.Println("error:", err)
		return
	}
	spec, _ := providers.Lookup(name)
	fmt.Println(spec.Name)
	// Output: example-out-of-tree
}
