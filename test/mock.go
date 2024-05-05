package test

import (
	"fmt"
	"os"

	"github.com/stretchr/testify/require"
)

type mockTest struct{}

func T() *mockTest { return &mockTest{} }

var _ require.TestingT = (*mockTest)(nil)

func (m *mockTest) Errorf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
	fmt.Println()

	os.Exit(1)
}

func (m *mockTest) FailNow() {
	fmt.Println("Fail")
	os.Exit(1)
}

type printTest struct{}

func P() *printTest { return &printTest{} }

func (m *printTest) Errorf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
	fmt.Println()
}

func (m *printTest) FailNow() {
	fmt.Println("FailNow")
}
