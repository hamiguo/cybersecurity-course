CC      = gcc
CFLAGS  = -O3 -march=native -Wall -Wextra -std=gnu11
LDFLAGS =

# 根据 CPU 检测是否支持 AES-NI 和 SSSE3
HAS_AES  ?= 1
HAS_SSSE3 ?= 1

SRC = main_test.c modes.c \
      aes_basic.c aes_ttable.c aes_shuffle.c aes_ni.c \
      sm4_basic.c sm4_ttable.c sm4_shuffle.c \
      gift128_basic.c gift128_bitslice.c \
      twine128_basic.c twine128_bitslice.c

OBJ = $(SRC:.c=.o)
TARGET = crypto_test

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)
