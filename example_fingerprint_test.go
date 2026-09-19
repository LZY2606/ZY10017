package sql_test

import (
	"fmt"
	"log"

	"github.com/rqlite/sql"
)

func ExampleFingerprintString() {
	first, err := sql.FingerprintString("SELECT id FROM users WHERE id = ?")
	if err != nil {
		log.Fatal(err)
	}
	second, err := sql.FingerprintString("select  id  from users -- bind follows\nwhere id=?42;")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(second == first)
	fmt.Println(len(first) == len(sql.FingerprintVersionV1)+64)
	// Output:
	// true
	// true
}

func ExampleFingerprintStatements() {
	fingerprints, err := sql.FingerprintStatements("SELECT 99; INSERT INTO users(name) VALUES ('Ada')")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(fingerprints))
	fmt.Println(len(fingerprints[1]) == len(sql.FingerprintVersionV1)+64)
	// Output:
	// 2
	// true
}
