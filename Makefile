PREFIX ?= $(HOME)/.local

.PHONY: build test check browser-test lint-extension install extension clean

build:
	mkdir -p bin
	go build -trimpath -o bin/pq ./cmd/pq
	go build -trimpath -o bin/pq-native ./cmd/pq-native

test:
	go test -race ./...

check: test
	go vet ./...
	node --test extension/*.test.js

browser-test: build
	python3 scripts/browser-smoke.py

lint-extension:
	npx --yes web-ext lint --source-dir extension --ignore-files '*.test.js'

install: build
	install -Dm755 bin/pq "$(PREFIX)/bin/pq"
	install -Dm755 bin/pq-native "$(PREFIX)/bin/pq-native"
	install -Dm644 packaging/pq.service "$(HOME)/.config/systemd/user/pq.service"
	@printf '\nInstalled. The service expects %%h/.local/bin/pq; override ExecStart if PREFIX differs.\n'

extension:
	rm -f pq-firefox.xpi
	cd extension && zip -j -X ../pq-firefox.xpi manifest.json background.js content.js popup.html popup.js popup.css security.js

clean:
	rm -rf bin pq-firefox.xpi
