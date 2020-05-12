package michi

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestMichi(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Michi Suite")
}
