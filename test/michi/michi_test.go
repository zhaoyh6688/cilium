package michi

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("michi", func() {
	It("returns something", func() {
		Expect(michi()).To(Equal(42))
	})
})
