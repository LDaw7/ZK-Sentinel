CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -O2
TARGET = bin/sensor
SRC = src/sensor.c

all: clean build requirements

build:
	mkdir -p bin
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

requirements:
	pip install -r requirements.txt

run:
	@echo "[*] Starting ZK-Sentinel Pipeline..."
	./$(TARGET) | python3 src/brain.py

clean:
	rm -rf bin