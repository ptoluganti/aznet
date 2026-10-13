APP_NAME := aznet
VERSION ?= 0.1.0
DIST_DIR := dist

LINUX_TARGET := x86_64-unknown-linux-gnu
MACOS_X86_TARGET := x86_64-apple-darwin
MACOS_ARM_TARGET := aarch64-apple-darwin
WINDOWS_TARGET := x86_64-pc-windows-gnu

.PHONY: all setup build build-linux build-macos build-windows package clean

all: package

setup:
	@rustup target add $(LINUX_TARGET) $(MACOS_X86_TARGET) $(MACOS_ARM_TARGET) $(WINDOWS_TARGET)

build: build-linux build-macos build-windows

build-linux:
	@cargo build --release --target $(LINUX_TARGET)

build-macos:
	@cargo build --release --target $(MACOS_X86_TARGET)
	@cargo build --release --target $(MACOS_ARM_TARGET)

build-windows:
	@cargo build --release --target $(WINDOWS_TARGET)

package: clean build
	@mkdir -p $(DIST_DIR)
	@cp target/$(LINUX_TARGET)/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-linux-x86_64
	@tar -czf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-linux-x86_64.tar.gz -C $(DIST_DIR) $(APP_NAME)-linux-x86_64
	@rm -f $(DIST_DIR)/$(APP_NAME)-linux-x86_64

	@cp target/$(MACOS_X86_TARGET)/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-macos-x86_64
	@tar -czf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-macos-x86_64.tar.gz -C $(DIST_DIR) $(APP_NAME)-macos-x86_64
	@rm -f $(DIST_DIR)/$(APP_NAME)-macos-x86_64

	@cp target/$(MACOS_ARM_TARGET)/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-macos-aarch64
	@tar -czf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-macos-aarch64.tar.gz -C $(DIST_DIR) $(APP_NAME)-macos-aarch64
	@rm -f $(DIST_DIR)/$(APP_NAME)-macos-aarch64

	@cp target/$(WINDOWS_TARGET)/release/$(APP_NAME).exe $(DIST_DIR)/$(APP_NAME)-windows-x86_64.exe
	@zip -j $(DIST_DIR)/$(APP_NAME)-$(VERSION)-windows-x86_64.zip $(DIST_DIR)/$(APP_NAME)-windows-x86_64.exe
	@rm -f $(DIST_DIR)/$(APP_NAME)-windows-x86_64.exe
	@echo "Packages created in $(DIST_DIR)"

clean:
	@rm -rf $(DIST_DIR)
	@cargo clean
