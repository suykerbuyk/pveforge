// Command pveforge-harness-secrets opens and seals the nested harness's
// age-encrypted secrets (hack/harness/secrets.age). It is run through
// hack/harness/unlock.sh; see internal/harnesssecrets.
package main

import (
	"os"

	"github.com/suykerbuyk/pveforge/internal/harnesssecrets"
)

func main() {
	os.Exit(harnesssecrets.Main(os.Args[1:], os.Environ(), os.Stdin, os.Stdout, os.Stderr))
}
