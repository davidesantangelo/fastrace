# Makefile for fastrace - high-performance traceroute implementation

# Compiler and flags
CC = gcc
CFLAGS = -O3 -Wall -Wextra
CFLAGS_DEBUG = -g -O0 -Wall -Wextra
LDFLAGS =

# Target binary
TARGET = fastrace
TARGET_DEBUG = fastrace_debug

# Source files
SRC = fastrace.c
HEADERS = 

# Installation directories
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

# Default target
all: $(TARGET)

# Standard optimized build
$(TARGET): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

# Debug build with debugging symbols
debug: $(TARGET_DEBUG)

$(TARGET_DEBUG): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS_DEBUG) -o $@ $(SRC) $(LDFLAGS)

# Maximum performance build with architecture-specific optimizations
optimized: $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) -march=native -mtune=native -flto -o $(TARGET) $(SRC) $(LDFLAGS)

# Install the program
install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

# Uninstall the program
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

# Clean up build artifacts
clean:
	rm -f $(TARGET) $(TARGET_DEBUG)

# Help target
help:
	@echo "Fastrace Makefile Usage:"
	@echo "  make              - Build standard optimized version"
	@echo "  make debug        - Build version with debugging symbols"
	@echo "  make optimized    - Build version with maximum performance optimizations"
	@echo "  make install      - Install fastrace to $(BINDIR)"
	@echo "  make uninstall    - Remove fastrace from $(BINDIR)"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make help         - Display this help message"
	@echo ""
	@echo "Note: Running fastrace requires root privileges."
	@echo "Usage: sudo fastrace <hostname>"

.PHONY: all debug optimized install uninstall clean help
