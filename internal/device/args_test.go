package device

import "testing"

func TestAppendArgsFragment(t *testing.T) {
	cases := []struct {
		name     string
		existing string
		fragment string
		want     string
	}{
		{"empty existing", "", "-device nvme,drive=d0", "-device nvme,drive=d0"},
		{"whitespace-only existing", "   ", "-device nvme,drive=d0", "-device nvme,drive=d0"},
		{"non-empty existing", "-cpu host", "-device nvme,drive=d0", "-cpu host -device nvme,drive=d0"},
		{"existing with trailing whitespace", "-cpu host  ", "-device nvme,drive=d0", "-cpu host -device nvme,drive=d0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := AppendArgsFragment(c.existing, c.fragment)
			if got != c.want {
				t.Errorf("AppendArgsFragment(%q, %q) = %q, want %q", c.existing, c.fragment, got, c.want)
			}
		})
	}
}
