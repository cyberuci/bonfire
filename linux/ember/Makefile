# Stripping flags to reduce binary size and remove debug information
LDFLAGS := -ldflags "-s -w"

# Define the list of binaries to be built
BINS := \
    scripts/fwp \
    ember-linux \
    ember-windows.exe \

.PHONY: all clean

# Default target: builds all specified platforms
all: $(BINS)

scripts/fwp:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $@ $(LDFLAGS) scripts/fw.go

ember-linux: scripts/fwp
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $@ $(LDFLAGS) .

ember-windows.exe: scripts/fwp
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o $@ $(LDFLAGS) .

clean:
	rm -f $(BINS)
	@echo "Cleaned build artifacts."
