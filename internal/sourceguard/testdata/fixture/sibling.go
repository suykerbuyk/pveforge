package fixture

// helperInSiblingFile is the whole point: a one-file text scan cannot see
// this, and the call-graph walk must.
func helperInSiblingFile() string {
	return "planted/in/a/sibling/file"
}
