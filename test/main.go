package main

import (
	"os"
)

func main() {
	f, err := os.OpenFile("test.txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		panic(err)
	}

	text := "some great stuff"
	n, err := f.Write([]byte(text))
	if err != nil {
		panic(err)
	}

	if len(text) != n {
		panic("Incomplete write.")
	}

	err = f.Sync()
	if err != nil {
		panic(err)
	}

	err = f.Close()
	if err != nil {
		panic(err)
	}
}
