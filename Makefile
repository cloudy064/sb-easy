# sb-easy (Go rewrite) — sing-box is embedded as a library, so the binary must
# be built with sing-box's feature build tags.
SINGBOX_TAGS := with_clash_api,with_gvisor,with_quic,with_wireguard,with_utls,with_dhcp
BIN := bin/sb-easy

.PHONY: build run tidy frontend clean
build:
	go build -tags "$(SINGBOX_TAGS)" -buildvcs=false -o $(BIN) ./cmd/sb-easy

run: build
	./$(BIN)

tidy:
	GOFLAGS=-mod=mod go mod tidy -e

frontend:
	cd frontend && npm install && npm run build

clean:
	rm -rf bin
