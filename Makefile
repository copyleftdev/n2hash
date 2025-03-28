.PHONY: build install uninstall clean

# Default target (build)
all: build

# Build the project
build:
	cargo build --release

# Install to user's local bin directory
install: build
	@echo "Installing n2hash to ~/.local/bin/"
	@mkdir -p ~/.local/bin
	@cp target/release/n2hash ~/.local/bin/
	@chmod +x ~/.local/bin/n2hash
	@echo "Installation complete. Make sure ~/.local/bin is in your PATH."
	@echo "You can add it by adding 'export PATH=\$$PATH:~/.local/bin' to your .bashrc or .zshrc"

# System-wide install (requires sudo)
install-system: build
	@echo "Installing n2hash system-wide to /usr/local/bin/"
	@sudo cp target/release/n2hash /usr/local/bin/
	@sudo chmod +x /usr/local/bin/n2hash
	@echo "System-wide installation complete."

# Uninstall from user's local bin
uninstall:
	@echo "Removing n2hash from ~/.local/bin/"
	@rm -f ~/.local/bin/n2hash
	@echo "Uninstallation complete."

# Uninstall from system-wide location (requires sudo)
uninstall-system:
	@echo "Removing n2hash from /usr/local/bin/"
	@sudo rm -f /usr/local/bin/n2hash
	@echo "System-wide uninstallation complete."

# Clean build artifacts
clean:
	cargo clean

# Help target
help:
	@echo "Available targets:"
	@echo "  make           - Build the project (same as 'make build')"
	@echo "  make build     - Build the project using cargo"
	@echo "  make install   - Install to user's ~/.local/bin directory"
	@echo "  make install-system - Install system-wide to /usr/local/bin (requires sudo)"
	@echo "  make uninstall - Remove from ~/.local/bin"
	@echo "  make uninstall-system - Remove from /usr/local/bin (requires sudo)"
	@echo "  make clean     - Remove build artifacts"
	@echo "  make help      - Show this help message"
