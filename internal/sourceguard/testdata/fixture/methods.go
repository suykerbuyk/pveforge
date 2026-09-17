package fixture

// Server exists so the fixture contains METHODS, not just plain functions.
// Without one, byQualified is populated but never consulted by any test in
// this package — and the two real consumers (internal/pve, internal/idempotent)
// reach it exclusively through qualified roots like "Client.ShutdownVM" and
// "VMShutdown.Apply". Review confirmed by mutation that removing the
// byQualified population entirely left this package's own tests passing.
type Server struct{ name string }

// Handle is reached only via the qualified root "Server.Handle". Its own
// token is distinct from Helper's so a test can tell which one was scanned.
func (s *Server) Handle() string {
	return "planted-in-Server-Handle" + s.helperMethod()
}

func (s *Server) helperMethod() string {
	return "planted-in-Server-helperMethod"
}

// Handle on a DIFFERENT receiver, with the same bare method name. A bare
// root "Handle" must reach both; the qualified root "Server.Handle" must
// reach only the one above.
type Worker struct{}

func (w Worker) Handle() string {
	return "planted-in-Worker-Handle"
}
