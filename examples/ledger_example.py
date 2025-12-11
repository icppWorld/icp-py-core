"""
Example demonstrating query and update calls to the ICP Ledger canister.

This example shows how to:
- Query account balance (query call)
- Query transfer fee (query call)
- Query token metadata (query call)
- Transfer tokens (update call)
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from icp_agent import Agent, Client
from icp_identity import Identity
from icp_canister import Ledger

# Configuration
CANISTER_ID = "ryjl3-tyaaa-aaaaa-aaaba-cai"  # ICP Ledger mainnet
ACCOUNT_HEX = "4874711516b70ef0f88a7ecd47baa266c4a554850ea6373e72cd4c43756ba8e2"


def main():
    """Main function demonstrating ledger interactions."""
    print("=" * 60)
    print("ICP Ledger Example")
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

    # Initialize Ledger canister
    try:
        ledger = Ledger(agent)
        print("[+] Ledger canister initialized")
    except Exception as e:
        print(f"[!] Failed to initialize ledger: {e}")
        import traceback
        traceback.print_exc()
        return

    # Example 1: Query call - Get account balance
    print("\n[1] Query Call: Get Account Balance")
    print("-" * 60)
    try:
        account_blob = bytes.fromhex(ACCOUNT_HEX)
        args = {'account': account_blob}
        result = ledger.account_balance(args)
        
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                tokens_dict = val['value']
                e8s = tokens_dict.get('e8s') or (list(tokens_dict.values())[0] if tokens_dict else None)
                if e8s is not None:
                    icp = e8s / 100_000_000.0
                    print(f"[+] Account balance: {icp:.8f} ICP ({e8s} e8s)")
                else:
                    print(f"[!] Unable to extract balance from: {tokens_dict}")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 2: Query call - Get transfer fee
    print("\n[2] Query Call: Get Transfer Fee")
    print("-" * 60)
    try:
        result = ledger.transfer_fee({})
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                fee_dict = val['value']
                transfer_fee = fee_dict.get('transfer_fee', {})
                fee_e8s = transfer_fee.get('e8s') or (list(transfer_fee.values())[0] if transfer_fee else None)
                if fee_e8s is not None:
                    fee_icp = fee_e8s / 100_000_000.0
                    print(f"[+] Transfer fee: {fee_icp:.8f} ICP ({fee_e8s} e8s)")
                else:
                    print(f"[!] Unable to extract fee from: {fee_dict}")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 3: Query call - Get token symbol
    print("\n[3] Query Call: Get Token Symbol")
    print("-" * 60)
    try:
        result = ledger.symbol()
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                symbol_dict = val['value']
                symbol = symbol_dict.get('symbol') or (list(symbol_dict.values())[0] if symbol_dict else None)
                if symbol:
                    print(f"[+] Token symbol: {symbol}")
                else:
                    print(f"[!] Unable to extract symbol from: {symbol_dict}")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 4: Query call - Get token name
    print("\n[4] Query Call: Get Token Name")
    print("-" * 60)
    try:
        result = ledger.name()
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                name_dict = val['value']
                name = name_dict.get('name') or (list(name_dict.values())[0] if name_dict else None)
                if name:
                    print(f"[+] Token name: {name}")
                else:
                    print(f"[!] Unable to extract name from: {name_dict}")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 5: Query call - Get decimals
    print("\n[5] Query Call: Get Token Decimals")
    print("-" * 60)
    try:
        result = ledger.decimals()
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                decimals_dict = val['value']
                decimals = decimals_dict.get('decimals') or (list(decimals_dict.values())[0] if decimals_dict else None)
                if decimals is not None:
                    print(f"[+] Token decimals: {decimals}")
                else:
                    print(f"[!] Unable to extract decimals from: {decimals_dict}")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 6: Query call - Get archives
    print("\n[6] Query Call: Get Archives")
    print("-" * 60)
    try:
        result = ledger.archives()
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                archives_dict = val['value']
                archives_list = archives_dict.get('archives') or (list(archives_dict.values())[0] if archives_dict else None)
                if archives_list:
                    print(f"[+] Found {len(archives_list)} archive canisters")
                    for i, archive in enumerate(archives_list[:3]):  # Show first 3
                        if isinstance(archive, dict):
                            canister_id = archive.get('canister_id') or (list(archive.values())[0] if archive else None)
                            if canister_id:
                                print(f"    Archive {i+1}: {canister_id}")
                else:
                    print("[+] No archives found")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Note: Update calls (like transfer) require authenticated identity and actual tokens
    # They are not demonstrated here to avoid accidental transactions
    print("\n" + "=" * 60)
    print("Note: Update calls (e.g., transfer) require authenticated")
    print("identity and actual tokens. They are not demonstrated here.")
    print("=" * 60)


if __name__ == "__main__":
    main()
