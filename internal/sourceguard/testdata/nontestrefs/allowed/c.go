package allowed

import "net/http"

// InAllowedDir is the in-boundary use an AllowDir permits. The anti-vacuity
// assertion looks for it BY NAME: if it stops being reported, the predicate
// has stopped matching and the guard is decoration. Mutant W3.
func InAllowedDir() *http.Client {
	return &http.Client{}
}
