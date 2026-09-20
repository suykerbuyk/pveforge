package sub

import "net/http"

// InSubdir proves the walk recurses rather than reading one directory, which
// is the difference between this and parser.ParseDir.
func InSubdir() *http.Client {
	return &http.Client{}
}
