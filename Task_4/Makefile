# Makefile for SM3 Optimized Implementation
# Supports: ARM64 NEON, x86 AVX2, x86 AVX-512, portable C

# ---- Compiler ----
CC      = gcc
CFLAGS  = -O3 -Wall -Wextra -std=c11 -pedantic
LDFLAGS = -lm

# ---- Architecture Detection ----
UNAME_M := $(shell uname -m)

# Default: portable C (no SIMD)
ARCH_FLAGS =
ARCH_SRCS  = sm3_ref.c

ifeq ($(UNAME_M),aarch64)
    # ARM64 with NEON
    ARCH_FLAGS = -march=armv8-a+simd -D__aarch64__
    ARCH_SRCS  = sm3_ref.c sm3_neon.c
    TARGET     = sm3_test_arm64
else ifeq ($(UNAME_M),x86_64)
    # x86_64 with AVX2 + AVX-512
    ARCH_FLAGS = -mavx2 -mavx512f -mavx512vl -D__x86_64__
    ARCH_SRCS  = sm3_ref.c sm3_avx2.c sm3_avx512.c
    TARGET     = sm3_test_x86
else
    # Fallback: portable only
    ARCH_FLAGS =
    ARCH_SRCS  = sm3_ref.c
    TARGET     = sm3_test_portable
endif

CFLAGS += $(ARCH_FLAGS)

# ---- Object Files ----
OBJS = $(ARCH_SRCS:.c=.o) sm3_test.o

# ---- Targets ----

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build successful: $(TARGET)"
	@echo "Run with: ./$(TARGET)"

%.o: %.c sm3.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Convenience targets for cross-compilation simulation
avx2: CFLAGS += -mavx2 -D__x86_64__
avx2: ARCH_SRCS = sm3_ref.c sm3_avx2.c
avx2: sm3_test_avx2

sm3_test_avx2: sm3_ref.o sm3_avx2.o sm3_test.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

avx512: CFLAGS += -mavx512f -mavx512vl -D__x86_64__
avx512: ARCH_SRCS = sm3_ref.c sm3_avx512.c
avx512: sm3_test_avx512

sm3_test_avx512: sm3_ref.o sm3_avx512.o sm3_test.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

neon: CFLAGS += -march=armv8-a+simd -D__aarch64__
neon: ARCH_SRCS = sm3_ref.c sm3_neon.c
neon: sm3_test_neon

sm3_test_neon: sm3_ref.o sm3_neon.o sm3_test.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f *.o sm3_test_* *~
	@echo "Cleaned."

# ---- Help ----
help:
	@echo "SM3 Optimized Implementation - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make          Auto-detect arch and build"
	@echo "  make avx2     Build x86 AVX2 version"
	@echo "  make avx512   Build x86 AVX-512 version"
	@echo "  make neon     Build ARM64 NEON version"
	@echo "  make test     Build and run tests"
	@echo "  make clean    Remove build artifacts"
	@echo ""
	@echo "Detected arch: $(UNAME_M)"
