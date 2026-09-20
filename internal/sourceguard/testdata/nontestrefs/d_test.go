package nontestrefs

import "net/http"

// InTestFile must never be reported: NonTestReferences walks non-test files
// only, which is the whole point of its name. Never compiled — this file is
// under testdata.
func InTestFile() *http.Client {
	return &http.Client{}
}
