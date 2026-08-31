#!/bin/bash
echo ""
echo "  ==================================="
echo "   NETSCOPE — Network Diagnostics"
echo "  ==================================="
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "  ERROR: Go is not installed."
    echo "  Download from: https://go.dev/dl/"
    exit 1
fi

echo "  Building NetScope..."
go build -o netscope ./cmd/netscope
if [ $? -ne 0 ]; then
    echo "  BUILD FAILED"
    exit 1
fi

echo "  Build successful!"
echo "  Starting server on http://localhost:8199"
echo ""
./netscope serve
