#!/bin/bash
# Verification script: simulate "clean environment" installation test
# This script runs in a Docker container to ensure installation works without Rust environment

set -e

echo "=========================================="
echo "Clean Environment Installation Test"
echo "=========================================="

# 1. Build wheel locally
echo "Step 1: Building wheel file..."
cd "$(dirname "$0")/.."
cd src/icp_candid/ic_candid_parser

# Check if maturin is installed
if ! command -v maturin &> /dev/null; then
    echo "Error: maturin is not installed. Please install it first: pip install maturin"
    exit 1
fi

# Build wheel
maturin build --release --out dist

echo "✓ Wheel file built successfully"
echo ""

# 2. Start a clean Python container (without Rust)
echo "Step 2: Testing installation in Docker container..."
echo ""

# Get the path of the built wheel file
WHEEL_FILE=$(ls -t dist/*.whl | head -n1)
echo "Found wheel file: $WHEEL_FILE"

# Run verification using Docker
docker run --rm -it \
    -v "$(pwd)/dist:/dist" \
    python:3.10-slim bash -c "
        set -e
        echo '=========================================='
        echo 'Docker Container Verification'
        echo '=========================================='
        echo ''
        
        # Check that Rust does not exist (should not exist)
        if command -v rustc &> /dev/null; then
            echo 'Warning: Rust compiler exists, this is not a clean environment!'
            exit 1
        fi
        echo '✓ Confirmed: Rust compiler does not exist (clean environment)'
        echo ''
        
        # Install the built package
        echo 'Installing wheel package...'
        pip install --no-cache-dir /dist/*.whl
        echo '✓ Installation successful'
        echo ''
        
        # Run verification script
        echo 'Verifying imports and functionality...'
        python -c '
import sys
print(f\"Python version: {sys.version}\")
print()

# Try importing main package
try:
    import icp_candid
    print(\"✓ icp_candid imported successfully\")
except ImportError as e:
    print(f\"✗ icp_candid import failed: {e}\")
    sys.exit(1)

# Try importing internal module, verify GLIBC compatibility
try:
    from icp_candid import _ic_candid_core
    print(\"✓ _ic_candid_core (Rust extension) imported successfully\")
except ImportError as e:
    print(f\"✗ _ic_candid_core import failed: {e}\")
    sys.exit(1)

# Verify function is available
try:
    result = _ic_candid_core.parse_did(\"service : {}\")
    print(\"✓ parse_did function call successful\")
except Exception as e:
    print(f\"✗ parse_did function call failed: {e}\")
    sys.exit(1)

# Verify dependencies are clean (should not error)
print()
print(\"Verifying dependency cleanup...\")
try:
    import antlr4
    print(\"⚠ Warning: ANTLR still exists! Should have been removed.\")
except ImportError:
    print(\"✓ ANTLR correctly removed\")

try:
    import leb128
    print(\"⚠ Warning: leb128 still exists! Should have been removed.\")
except ImportError:
    print(\"✓ leb128 correctly removed\")

print()
print(\"==========================================\")
print(\"✓ All verifications passed! Installation and import test successful!\")
print(\"==========================================\")
        '
    "

echo ""
echo "=========================================="
echo "✓ Verification completed!"
echo "=========================================="
