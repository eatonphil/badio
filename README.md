# badio

ptrace layer for triggering bad IO behavior.

Example:

```
$ make
$ (cd test && go build main.go)
$ cat test/main.go
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
$ ./main test/main
Got a write on 3: some great stu
$ cat test.txt
some great stu
```

## Notes

* https://nullprogram.com/blog/2018/06/23/
* https://webdocs.cs.ualberta.ca/~paullu/C498/meng.ptrace.slides.pdf
* https://linux.die.net/man/2/ptrace
* https://man7.org/linux/man-pages/man2/write.2.html
* Calling convention https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f

On Go writes on Linux:
* https://cs.opensource.google/go/go/+/refs/tags/go1.21.1:src/internal/poll/fd_unix.go
