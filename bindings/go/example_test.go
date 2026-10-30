// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

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

func Example_card() {
	pk, sk, err := noqtis.SignKeyGen("ML-DSA-65", nil)
	if err != nil {
		panic(err)
	}
	f := noqtis.CardFields{Name: "Ada Lovelace",
		ORCID: "https://orcid.org/0000-0002-1825-0097",
		URL:   "https://example.org/ada"}
	card, err := noqtis.MakeCard("ML-DSA-65", sk, pk, f, time.Time{})
	if err != nil {
		panic(err)
	}
	c, _ := noqtis.VerifyCard(card, pk) // nil unless it verifies and is pk's
	fmt.Println("name:", c.Name)
	fmt.Println("orcid:", c.ORCID)

	// a changed card does not verify; a wrong check digit is refused
	bad := bytes.Replace(card, []byte("Ada"), []byte("Eve"), 1)
	c, _ = noqtis.VerifyCard(bad, nil)
	fmt.Println("changed:", c == nil)
	f.ORCID = "0000-0002-1825-0098"
	_, err = noqtis.MakeCard("ML-DSA-65", sk, pk, f, time.Time{})
	fmt.Println("refused:", errors.Is(err, noqtis.ErrArg))
	// Output:
	// name: Ada Lovelace
	// orcid: 0000-0002-1825-0097
	// changed: true
	// refused: true
}
