"""
Example demonstrating query and update calls to the ICP Cycles Wallet canister.

This example shows how to:
- Query wallet balance (query call)
- Query wallet API version (query call)
- Query wallet name (query call)
- Query controllers (query call)
- Send cycles (update call - requires cycles)
- Create canister (update call - requires cycles)
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from icp_agent import Agent, Client
from icp_identity import Identity
from icp_canister import CyclesWallet

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
        print(f"[!] Network connection failed: {e}")
        import traceback
        traceback.print_exc()
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
        print(f"[!] Failed to initialize cycles wallet: {e}")
        import traceback
        traceback.print_exc()
        return

    # Example 1: Query call - Get wallet API version
    print("\n[1] Query Call: Get Wallet API Version")
    print("-" * 60)
    try:
        result = wallet.wallet_api_version()
        if isinstance(result, list) and len(result) > 0:
            version = result[0]
            print(f"[+] Wallet API version: {version}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 2: Query call - Get wallet name
    print("\n[2] Query Call: Get Wallet Name")
    print("-" * 60)
    try:
        result = wallet.name()
        if isinstance(result, list) and len(result) > 0:
            name = result[0]
            if name:
                print(f"[+] Wallet name: {name}")
            else:
                print("[+] Wallet name: (not set)")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 3: Query call - Get wallet balance
    print("\n[3] Query Call: Get Wallet Balance")
    print("-" * 60)
    try:
        result = wallet.wallet_balance()
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                balance_dict = val['value']
                amount = balance_dict.get('amount') or (list(balance_dict.values())[0] if balance_dict else None)
                if amount is not None:
                    cycles = amount / 1_000_000_000_000.0  # Convert to T cycles
                    print(f"[+] Wallet balance: {cycles:.6f} T cycles ({amount} cycles)")
                else:
                    print(f"[!] Unable to extract balance from: {balance_dict}")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 4: Query call - Get wallet balance (128-bit version)
    print("\n[4] Query Call: Get Wallet Balance (128-bit)")
    print("-" * 60)
    try:
        result = wallet.wallet_balance128()
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                balance_dict = val['value']
                amount = balance_dict.get('amount') or (list(balance_dict.values())[0] if balance_dict else None)
                if amount is not None:
                    cycles = amount / 1_000_000_000_000.0  # Convert to T cycles
                    print(f"[+] Wallet balance (128-bit): {cycles:.6f} T cycles ({amount} cycles)")
                else:
                    print(f"[!] Unable to extract balance from: {balance_dict}")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 5: Query call - Get controllers
    print("\n[5] Query Call: Get Controllers")
    print("-" * 60)
    try:
        result = wallet.get_controllers()
        if isinstance(result, list) and len(result) > 0:
            controllers = result[0]
            if isinstance(controllers, list):
                print(f"[+] Found {len(controllers)} controllers")
                for i, controller in enumerate(controllers[:5]):  # Show first 5
                    print(f"    Controller {i+1}: {controller}")
            else:
                print(f"[!] Unexpected controllers format: {controllers}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 6: Query call - Get custodians
    print("\n[6] Query Call: Get Custodians")
    print("-" * 60)
    try:
        result = wallet.get_custodians()
        if isinstance(result, list) and len(result) > 0:
            custodians = result[0]
            if isinstance(custodians, list):
                print(f"[+] Found {len(custodians)} custodians")
                for i, custodian in enumerate(custodians[:5]):  # Show first 5
                    print(f"    Custodian {i+1}: {custodian}")
            else:
                print(f"[!] Unexpected custodians format: {custodians}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 7: Query call - List addresses
    print("\n[7] Query Call: List Addresses")
    print("-" * 60)
    try:
        result = wallet.list_addresses()
        if isinstance(result, list) and len(result) > 0:
            addresses = result[0]
            if isinstance(addresses, list):
                print(f"[+] Found {len(addresses)} addresses in address book")
                for i, address in enumerate(addresses[:3]):  # Show first 3
                    if isinstance(address, dict):
                        addr_id = address.get('id') or (list(address.values())[0] if address else None)
                        name = address.get('name')
                        print(f"    Address {i+1}: ID={addr_id}, Name={name or 'N/A'}")
            else:
                print(f"[!] Unexpected addresses format: {addresses}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Note: Update calls require authenticated identity and cycles
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
