// Package nontestrefs is NonTestReferences' fixture. Every file in it exists
// to make one specific way of getting the walk wrong observable; the mutant
// each one kills is named in its comment.
package nontestrefs

import "net/http"

// Client is a bare identifier deliberately sharing a name with http.Client's
// Sel. A walker whose bare-name form also matched the right-hand side of a
// selector would conflate the two — in the real module that is 2 intended
// hits against 86. Mutant W5.
type Client struct {
	Doer *http.Client
}

// New builds one, so `Client` appears as a composite-literal type as well as
// a declaration.
func New() *Client {
	return &Client{Doer: &http.Client{}}
}

// Fetch calls Do through a FIELD selector, so the matched selector's X is
// itself a selector rather than an identifier. That is the shape a method
// call takes, and it is why AnyQualifier exists: parsing alone cannot know
// c.Doer's type.
func (c *Client) Fetch(req *http.Request) error {
	_, err := c.Doer.Do(req)
	return err
}
