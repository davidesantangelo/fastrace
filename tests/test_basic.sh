#!/bin/bash
# Basic test script for fastrace

if [ ! -f "./fastrace" ]; then
    echo "Error: fastrace binary not found. Run make first."
    exit 1
fi

echo "Running fastrace version check..."
./fastrace -V
if [ $? -ne 0 ]; then
    echo "Version check failed"
    exit 1
fi

echo "Running fastrace help check..."
./fastrace -h > /dev/null
if [ $? -ne 0 ]; then
    echo "Help check failed"
    exit 1
fi

echo "Running fastrace against localhost (requires sudo)..."
if [ "$EUID" -ne 0 ]; then 
    echo "Please run this test as root/sudo"
    exit 1
fi

./fastrace -m 5 -q 1 127.0.0.1
if [ $? -ne 0 ]; then
    echo "Localhost trace failed"
    exit 1
fi

echo "Tests passed!"
