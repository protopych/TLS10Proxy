PROGNAME := tls10proxy
MAIN := ./cmd/tls10proxy

OUTSUFFIX := bin/$(PROGNAME)
INSTALL_DIR := /opt/tls10proxy
INSTALL_PATH := $(INSTALL_DIR)/$(PROGNAME)

SERVICE_SOURCE := deploy/tls10proxy.service
SERVICE_NAME := tls10proxy.service
SERVICE_DEST := /etc/systemd/system/$(SERVICE_NAME)

FAIL2BAN_FILTER_DIR := /etc/fail2ban/filter.d
FAIL2BAN_JAIL_DIR := /etc/fail2ban/jail.d

FAIL2BAN_FILTER_SOURCE := deploy/fail2ban/filter.d
FAIL2BAN_JAIL_SOURCE := deploy/fail2ban/jail.d/tls10proxy.local

LDFLAGS_NATIVE := -ldflags '-s -w'
GO := go

.PHONY: all build run install uninstall clean test fmt vet

all: build

build:
	@mkdir -p bin
	$(GO) build $(LDFLAGS_NATIVE) -o $(OUTSUFFIX) $(MAIN)

run: build
	./$(OUTSUFFIX) $(ARGS)

install: build
	install -d $(INSTALL_DIR)
	install -m 0755 $(OUTSUFFIX) $(INSTALL_PATH)
	install -m 0644 $(SERVICE_SOURCE) $(SERVICE_DEST)
	systemctl daemon-reload
	systemctl restart $(SERVICE_NAME)

uninstall:
	systemctl disable --now $(SERVICE_NAME) 2>/dev/null || true
	rm -f $(SERVICE_DEST)
	rm -f $(INSTALL_PATH)
	systemctl daemon-reload

install-fail2ban:
	install -d $(FAIL2BAN_FILTER_DIR)
	install -d $(FAIL2BAN_JAIL_DIR)

	install -m 0644 \
		$(FAIL2BAN_FILTER_SOURCE)/tls10proxy-no-credentials.conf \
		$(FAIL2BAN_FILTER_DIR)/tls10proxy-no-credentials.conf

	install -m 0644 \
		$(FAIL2BAN_FILTER_SOURCE)/tls10proxy-credentials-mismatch.conf \
		$(FAIL2BAN_FILTER_DIR)/tls10proxy-credentials-mismatch.conf

	install -m 0644 \
		$(FAIL2BAN_FILTER_SOURCE)/tls10proxy-decode-error.conf \
		$(FAIL2BAN_FILTER_DIR)/tls10proxy-decode-error.conf

	install -m 0644 \
		$(FAIL2BAN_JAIL_SOURCE) \
		$(FAIL2BAN_JAIL_DIR)/tls10proxy.local

	fail2ban-client -t
	systemctl restart fail2ban

uninstall-fail2ban:
	rm -f $(FAIL2BAN_FILTER_DIR)/tls10proxy-no-credentials.conf
	rm -f $(FAIL2BAN_FILTER_DIR)/tls10proxy-credentials-mismatch.conf
	rm -f $(FAIL2BAN_FILTER_DIR)/tls10proxy-decode-error.conf
	rm -f $(FAIL2BAN_JAIL_DIR)/tls10proxy.local
	systemctl restart fail2ban

clean:
	rm -rf bin

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...
