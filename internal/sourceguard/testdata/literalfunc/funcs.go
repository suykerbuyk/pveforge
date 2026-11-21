package lit

type T struct{}

type G[K any] struct{}

type H[K, V any] struct{}

var pkgLevel = func() string { return "MARK" }

func plain() string { return "MARK" }

func (T) value() string { return "MARK" }

func (t *T) pointer() string { return "MARK" }

func (g *G[K]) generic() string { return "MARK" }

func (h H[K, V]) generic2() string { return "MARK" }

func closure() func() string {
	return func() string { return "MARK" }
}
