package outer

import "strings"

// tagsHave reports whether the PVE `tags` value carries tag as one of its
// parts, an exact case-sensitive match — a port of lib.sh:463-467
// (_harness_tags_have), which reproduces PVE::Tools::split_list: split on
// NUL when the value holds one, else on commas, semicolons and ASCII
// whitespace (space \t \n \v \f \r). The split is on PVE's own delimiters
// only, so a tag that merely contains the harness tag as a substring never
// matches.
func tagsHave(tags, tag string) bool {
	var parts []string
	if strings.IndexByte(tags, 0) >= 0 {
		parts = strings.Split(tags, "\x00")
	} else {
		parts = strings.FieldsFunc(tags, func(r rune) bool {
			switch r {
			case ',', ';', ' ', '\t', '\n', '\v', '\f', '\r':
				return true
			}
			return false
		})
	}
	for _, p := range parts {
		if p == tag {
			return true
		}
	}
	return false
}
