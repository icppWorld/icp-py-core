"""
Example demonstrating query calls to the ICP Cycles Wallet canister.

This example shows how to:
- Query wallet API version
- Query wallet name
- Query wallet balance (64-bit and 128-bit)
- Query controllers and custodians
- List addresses

Note: Update calls (e.g., wallet_send, wallet_create_canister) require
authenticated identity and actual cycles. They are not demonstrated here.
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from icp_agent import Agent, Client
from icp_identity import Identity
from icp_canister import CyclesWallet
from helpers import get_result_value, safe_get_nested_value, print_section, handle_exception

# Configuration
# Note: Replace with your actual cycles wallet canister ID
WALLET_CANISTER_ID = "YOUR_WALLET_CANISTER_ID_HERE"


def main():
    """Main function demonstrating cycles wallet interactions."""
    print("=" * 60)
    print("ICP Cycles Wallet Example")
    print("=" * 60)
    
    # Connect to IC mainnet
    try:
        client = Client(url="https://ic0.app")
        identity = Identity(anonymous=True)
        agent = Agent(identity, client)
        print("[+] Connected to IC mainnet")
    except Exception as e:
        handle_exception("Network connection", e)
        return

    # Check if wallet ID is configured
    if WALLET_CANISTER_ID == "YOUR_WALLET_CANISTER_ID_HERE":
        print("\n[!] Warning: Please set WALLET_CANISTER_ID in the script")
        print("    to your cycles wallet canister ID.")
        print("\n    Example usage:")
        print("    ```python")
        print("    wallet = CyclesWallet(agent, 'your-wallet-canister-id')")
        print("    ```")
        return

    # Initialize Cycles Wallet canister
    try:
        wallet = CyclesWallet(agent, WALLET_CANISTER_ID)
        print(f"[+] Cycles wallet canister initialized: {WALLET_CANISTER_ID}")
    except Exception as e:
        handle_exception("Cycles wallet initialization", e)
        return

    # Example 1: Query wallet API version
    print_section("[1] Query Call: Get Wallet API Version")
    try:
        result = wallet.wallet_api_version()
        version = get_result_value(result)
        if version is not None:
            print(f"[+] Wallet API version: {version}")
    except Exception as e:
        handle_exception("Query wallet API version", e)

    # Example 2: Query wallet name
    print_section("[2] Query Call: Get Wallet Name")
    try:
        result = wallet.name()
        name = get_result_value(result)
        if name:
            print(f"[+] Wallet name: {name}")
        else:
            print("[+] Wallet name: (not set)")
    except Exception as e:
        handle_exception("Query wallet name", e)

    # Example 3: Query wallet balance
    print_section("[3] Query Call: Get Wallet Balance")
    try:
        result = wallet.wallet_balance()
        balance_dict = get_result_value(result)
        if balance_dict:
            amount = safe_get_nested_value(balance_dict, 'amount') or (list(balance_dict.values())[0] if balance_dict else None)
            if amount is not None:
                cycles = amount / 1_000_000_000_000.0  # Convert to T cycles
                print(f"[+] Wallet balance: {cycles:.6f} T cycles ({amount} cycles)")
    except Exception as e:
        handle_exception("Query wallet balance", e)

    # Example 4: Query wallet balance (128-bit version)
    print_section("[4] Query Call: Get Wallet Balance (128-bit)")
    try:
        result = wallet.wallet_balance128()
        balance_dict = get_result_value(result)
        if balance_dict:
            amount = safe_get_nested_value(balance_dict, 'amount') or (list(balance_dict.values())[0] if balance_dict else None)
            if amount is not None:
                cycles = amount / 1_000_000_000_000.0  # Convert to T cycles
                print(f"[+] Wallet balance (128-bit): {cycles:.6f} T cycles ({amount} cycles)")
    except Exception as e:
        handle_exception("Query wallet balance (128-bit)", e)

    # Example 5: Query controllers
    print_section("[5] Query Call: Get Controllers")
    try:
        result = wallet.get_controllers()
        controllers = get_result_value(result)
        if isinstance(controllers, list):
            print(f"[+] Found {len(controllers)} controllers")
            for i, controller in enumerate(controllers[:5]):  # Show first 5
                print(f"    Controller {i+1}: {controller}")
    except Exception as e:
        handle_exception("Query controllers", e)

    # Example 6: Query custodians
    print_section("[6] Query Call: Get Custodians")
    try:
        result = wallet.get_custodians()
        custodians = get_result_value(result)
        if isinstance(custodians, list):
            print(f"[+] Found {len(custodians)} custodians")
            for i, custodian in enumerate(custodians[:5]):  # Show first 5
                print(f"    Custodian {i+1}: {custodian}")
    except Exception as e:
        handle_exception("Query custodians", e)

    # Example 7: Query addresses
    print_section("[7] Query Call: List Addresses")
    try:
        result = wallet.list_addresses()
        addresses = get_result_value(result)
        if isinstance(addresses, list):
            print(f"[+] Found {len(addresses)} addresses in address book")
            for i, address in enumerate(addresses[:3]):  # Show first 3
                if isinstance(address, dict):
                    addr_id = address.get('id') or (list(address.values())[0] if address else None)
                    name = address.get('name')
                    print(f"    Address {i+1}: ID={addr_id}, Name={name or 'N/A'}")
    except Exception as e:
        handle_exception("Query addresses", e)

    print("\n" + "=" * 60)
    print("Note: Update calls (e.g., wallet_send, wallet_create_canister)")
    print("require authenticated identity and actual cycles. They are not")
    print("demonstrated here to avoid accidental operations.")
    print("\nExample update call usage:")
    print("```python")
    print("# Send cycles")
    print("wallet.wallet_send({")
    print("    'canister': target_canister_id,")
    print("    'amount': 1_000_000_000_000  # 1 T cycles")
    print("})")
    print("```")
    print("=" * 60)


if __name__ == "__main__":
    main()
