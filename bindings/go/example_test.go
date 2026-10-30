// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rootcoder007/noqtis/bindings/go"
)

func Example_sign() {
	pk, sk, err := noqtis.SignKeyGen("ML-DSA-65", nil)
	if err != nil {
		panic(err)
	}
	o := &noqtis.SignOpts{Ctx: []byte("app-v1")}
	msg := []byte("the results in table 2")
	sig, err := noqtis.Sign("ML-DSA-65", sk, msg, o)
	if err != nil {
		panic(err)
	}
	fmt.Println("signature:", len(sig), "bytes")
	ok, _ := noqtis.Verify("ML-DSA-65", pk, msg, sig, o)
	fmt.Println("verify:", ok)
	ok, _ = noqtis.Verify("ML-DSA-65", pk, []byte("other"), sig, o)
	fmt.Println("other message:", ok)
	// Output:
	// signature: 3309 bytes
	// verify: true
	// other message: false
}

func Example_seal() {
	// a folder with some results
	d, _ := os.MkdirTemp("", "noqtis-go-demo")
	defer os.RemoveAll(d)
	os.MkdirAll(filepath.Join(d, "data"), 0o755)
	os.WriteFile(filepath.Join(d, "data", "in.csv"), []byte("a,b\n1,2\n"), 0o644)
	os.WriteFile(filepath.Join(d, "report.txt"), []byte("r\n"), 0o644)

	// seal it, then check it with the public key pinned
	pk, sk, _ := noqtis.SignKeyGen("ML-DSA-65", nil)
	if err := noqtis.Seal(d, "ML-DSA-65", sk, pk, `{"project":"tutorial"}`); err != nil {
		panic(err)
	}
	o := &noqtis.CheckOpts{Trust: pk}
	r, err := noqtis.Check(d, o)
	if err != nil {
		panic(err)
	}
	fmt.Printf("check: %v (%d checks)\n", r.OK(), len(r.Rows))

	// change a file: the check fails and says why
	os.WriteFile(filepath.Join(d, "report.txt"), []byte("r\nedited\n"), 0o644)
	r, _ = noqtis.Check(d, o)
	fmt.Println("after edit:", r.OK())
	for _, row := range r.Failed() {
		fmt.Println("FAIL", row.Check, row.Detail)
	}
	// Output:
	// check: true (22 checks)
	// after edit: false
	// FAIL file report.txt: size differs
}
