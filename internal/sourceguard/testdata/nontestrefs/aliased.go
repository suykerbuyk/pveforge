package nontestrefs

import nethttp "net/http"

// Aliased is mutant W6: a walker that resolved a qualified target by the
// qualifier's TEXT rather than through this file's import declarations would
// miss every reference here, and a one-line alias would defeat the guard.
func Aliased() *nethttp.Client {
	return &nethttp.Client{}
}
