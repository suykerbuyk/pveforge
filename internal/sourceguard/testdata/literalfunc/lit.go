package lit

import (
	"DELETE"
	"fmt"
)

// Literal targets: lines 10 and 11 match "DELETE"; nothing else here does.
func literals() {
	fmt.Println("DELETE")
	fmt.Println(`DELETE`)
	fmt.Println("DELETEX")
	fmt.Println("delete")
	fmt.Println(DELETE)
	fmt.Println("DEL" + "ETE")
	fmt.Println('D')
}

var DELETE = 1
