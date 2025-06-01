#!/bin/bash
# YubiKey Challenge-Response Setup for Brunnen-G
# Sets up slot 2 for TPM metadata protection

set -euo pipefail

echo "=== YubiKey Setup for Brunnen-G ==="

# Check if ykman is installed
if ! command -v ykman >/dev/null; then
    echo "Error: ykman not installed. Install with: pip3 install yubikey-manager"
    exit 1
fi

# Check if YubiKey is present
if ! ykman list >/dev/null 2>&1; then
    echo "Error: No YubiKey detected. Insert YubiKey and try again."
    exit 1
fi

echo "YubiKey detected:"
ykman list

# Check current OTP slot status
echo -e "\nCurrent OTP slot status:"
ykman otp info

# Check if slot 2 is already configured
slot2_status=$(ykman otp info | grep "Slot 2:" | cut -d: -f2 | xargs)

if [[ "$slot2_status" == "programmed" ]]; then
    echo -e "\nWarning: Slot 2 is already programmed."
    echo "This will overwrite the existing configuration in slot 2."
    read -p "Continue? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Setup cancelled."
        exit 0
    fi
fi

# Ask if user wants to use existing secret or generate new one
echo -e "\nSetup options:"
echo "1) Generate new secret (recommended for first YubiKey)"
echo "2) Use existing secret (for backup YubiKey)"
read -p "Choose option (1-2): " option

case $option in
    1)
        echo -e "\nGenerating new challenge-response secret..."
        ykman otp chalresp --touch 2 --generate --force
        echo "✓ Slot 2 configured with new secret"
        ;;
    2)
        echo "Error: Backup key setup requires manual configuration"
        echo "Use: ykman otp chalresp --touch 2 [your-secret]"
        exit 1
        ;;
    *)
        echo "Invalid option"
        exit 1
        ;;
esac

# Test the configuration
echo -e "\nTesting challenge-response..."
test_challenge="deadbeef"
echo "Sending test challenge: $test_challenge"
echo "Touch your YubiKey when it blinks..."

response=$(ykchalresp -2 -x "$test_challenge" 2>/dev/null || echo "FAILED")

if [[ "$response" == "FAILED" ]]; then
    echo "✗ Test failed. Check YubiKey configuration."
    exit 1
else
    echo "✓ Test successful. Response: $response"
fi

# Show final status
echo -e "\nFinal OTP slot status:"
ykman otp info

echo -e "\n=== Setup Complete ==="
echo "YubiKey slot 2 is now configured for Brunnen-G metadata protection."
echo "Copy the randomly generated key (hex) and save it securely - this is your backup in case you lose your yubikey"
echo ""
echo "Next steps:"
echo "1. Test metadata protection: python3 tmp_metadata_protection.py"
echo "2. For backup YubiKey: run this script again with option 2"