SRCS=$(wildcard atoll/*.go) main.go

.PHONY: passgen
passgen: passgen-linux passgen-linux-x86 passgen-darwin passgen-windows.exe passgen-windows-x86.exe

passgen-linux:
	GOOS=linux GOARCH=amd64 go build -o $@

passgen-linux-x86: $(SRCS)
	GOOS=linux GOARCH=386 go build -o $@

passgen-darwin: $(SRCS)
	GOOS=darwin GOARCH=arm64 go build -o $@

passgen-windows.exe: $(SRCS)
	GOOS=windows GOARCH=amd64 go build -o $@

passgen-windows-x86.exe: $(SRCS)
	GOOS=windows GOARCH=386 go build -o $@
