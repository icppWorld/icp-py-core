"""
Example demonstrating query calls to the ICP Ledger canister.

This example shows how to:
- Query account balance
- Query transfer fee
- Query token metadata (symbol, name, decimals)
- Query archive canisters

Note: Update calls (like transfer) require authenticated identity and actual tokens.
They are not demonstrated here to avoid accidental transactions.
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from icp_agent import Agent, Client
from icp_identity import Identity
from icp_canister import Ledger
from helpers import get_result_value, safe_get_nested_value, print_section, handle_exception

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
        handle_exception("Network connection", e)
        return

    # Initialize Ledger canister
    try:
        ledger = Ledger(agent)
        print("[+] Ledger canister initialized")
    except Exception as e:
        handle_exception("Ledger initialization", e)
        return

    # Example 1: Query account balance
    print_section("[1] Query Call: Get Account Balance")
    try:
        account_blob = bytes.fromhex(ACCOUNT_HEX)
        result = ledger.account_balance({'account': account_blob})
        
        tokens_dict = get_result_value(result)
        if tokens_dict:
            e8s = safe_get_nested_value(tokens_dict, 'e8s') or (list(tokens_dict.values())[0] if tokens_dict else None)
            if e8s is not None:
                icp = e8s / 100_000_000.0
                print(f"[+] Account balance: {icp:.8f} ICP ({e8s} e8s)")
    except Exception as e:
        handle_exception("Query account balance", e)

    # Example 2: Query transfer fee
    print_section("[2] Query Call: Get Transfer Fee")
    try:
        result = ledger.transfer_fee({})
        fee_dict = get_result_value(result)
        if fee_dict:
            transfer_fee = fee_dict.get('transfer_fee', {})
            fee_e8s = safe_get_nested_value(transfer_fee, 'e8s') or (list(transfer_fee.values())[0] if transfer_fee else None)
            if fee_e8s is not None:
                fee_icp = fee_e8s / 100_000_000.0
                print(f"[+] Transfer fee: {fee_icp:.8f} ICP ({fee_e8s} e8s)")
    except Exception as e:
        handle_exception("Query transfer fee", e)

    # Example 3: Query token symbol
    print_section("[3] Query Call: Get Token Symbol")
    try:
        result = ledger.symbol()
        symbol_dict = get_result_value(result)
        if symbol_dict:
            symbol = symbol_dict.get('symbol') or (list(symbol_dict.values())[0] if symbol_dict else None)
            if symbol:
                print(f"[+] Token symbol: {symbol}")
    except Exception as e:
        handle_exception("Query token symbol", e)

    # Example 4: Query token name
    print_section("[4] Query Call: Get Token Name")
    try:
        result = ledger.name()
        name_dict = get_result_value(result)
        if name_dict:
            name = name_dict.get('name') or (list(name_dict.values())[0] if name_dict else None)
            if name:
                print(f"[+] Token name: {name}")
    except Exception as e:
        handle_exception("Query token name", e)

    # Example 5: Query token decimals
    print_section("[5] Query Call: Get Token Decimals")
    try:
        result = ledger.decimals()
        decimals_dict = get_result_value(result)
        if decimals_dict:
            decimals = decimals_dict.get('decimals') or (list(decimals_dict.values())[0] if decimals_dict else None)
            if decimals is not None:
                print(f"[+] Token decimals: {decimals}")
    except Exception as e:
        handle_exception("Query token decimals", e)

    # Example 6: Query archives
    print_section("[6] Query Call: Get Archives")
    try:
        result = ledger.archives()
        archives_dict = get_result_value(result)
        if archives_dict:
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
    except Exception as e:
        handle_exception("Query archives", e)

    print("\n" + "=" * 60)
    print("Note: Update calls (e.g., transfer) require authenticated")
    print("identity and actual tokens. They are not demonstrated here.")
    print("=" * 60)


if __name__ == "__main__":
    main()
