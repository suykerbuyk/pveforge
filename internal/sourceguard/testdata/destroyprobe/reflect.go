package probe

// Reflection by name.
func byReflection(c any) {
	m := reflect.ValueOf(c).MethodByName("DestroyVM")
	_ = m
}
