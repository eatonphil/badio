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
	_, _ = f.Write([]byte(text))

	_ = f.Close()
}
