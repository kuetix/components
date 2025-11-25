package tests

import (
	"github.com/kuetix/components/modules"
	"github.com/kuetix/engine/tests"
)

func BootstrapTest() {
	tests.BootstrapTest()
	modules.Enable()
}
