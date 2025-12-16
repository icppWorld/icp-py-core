"""
Complete example of interacting with ICP Ledger Canister using a private key.

This example demonstrates how to:
1. Create Identity from PEM format private key
2. Query account balance
3. Query transfer fee
4. Execute transfer operation
5. Query balance again to confirm transfer result

Note: This example uses a real private key and mainnet, and will execute real transfer operations.
"""

import sys
import os
import time

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from icp_agent import Agent, Client
from icp_identity import Identity
from icp_canister import Ledger
from icp_principal import Principal
from helpers import get_result_value, safe_get_nested_value, print_section, handle_exception

# Private key configuration
PRIVATE_KEY_PEM = """PRIVATE_KEY_PEM"""

# ICP Ledger Canister ID (mainnet)
LEDGER_CANISTER_ID = "ryjl3-tyaaa-aaaaa-aaaba-cai"

# Test transfer target account (can be changed to any valid account identifier)
# This uses an example account, replace with a real receiver account in actual use
# Note: If transferring to self, you can use the same account identifier
TEST_RECEIVER_ACCOUNT_HEX = "4874711516b70ef0f88a7ecd47baa266c4a554850ea6373e72cd4c43756ba8e2"

# Whether to execute real transfer (set to False to skip transfer step)
ENABLE_TRANSFER = True

# Transfer mode: 'self' means transfer to self (safer), 'other' means transfer to other account
TRANSFER_MODE = 'self'  # Options: 'self' or 'other'


def e8s_to_icp(e8s):
    """Convert e8s to ICP"""
    return e8s / 100_000_000.0


def icp_to_e8s(icp):
    """Convert ICP to e8s"""
    return int(icp * 100_000_000)


def get_account_balance(ledger, account_id_bytes):
    """Query account balance"""
    try:
        result = ledger.account_balance({'account': account_id_bytes})
        tokens_dict = get_result_value(result)
        if tokens_dict:
            e8s = safe_get_nested_value(tokens_dict, 'e8s') or (list(tokens_dict.values())[0] if tokens_dict else None)
            return e8s
        return None
    except Exception as e:
        handle_exception("Query account balance", e)
        return None


def get_transfer_fee(ledger):
    """Query transfer fee"""
    try:
        result = ledger.transfer_fee({})
        fee_dict = get_result_value(result)
        if fee_dict:
            transfer_fee = fee_dict.get('transfer_fee', {})
            fee_e8s = safe_get_nested_value(transfer_fee, 'e8s') or (list(transfer_fee.values())[0] if transfer_fee else None)
            return fee_e8s
        return None
    except Exception as e:
        handle_exception("Query transfer fee", e)
        return None


def transfer_icp(ledger, to_account_bytes, amount_e8s, fee_e8s, memo=0):
    """Execute ICP transfer"""
    try:
        # Get current timestamp (nanoseconds)
        current_time_nanos = int(time.time() * 1_000_000_000)
        
        transfer_args = {
            'memo': memo,
            'amount': {'e8s': amount_e8s},
            'fee': {'e8s': fee_e8s},
            'to': to_account_bytes,
            'from_subaccount': None,  # Use default subaccount
            'created_at_time': {'timestamp_nanos': current_time_nanos}
        }
        
        print(f"[*] Executing transfer...")
        print(f"    Target account: 0x{to_account_bytes.hex()}")
        print(f"    Transfer amount: {e8s_to_icp(amount_e8s):.8f} ICP ({amount_e8s} e8s)")
        print(f"    Fee: {e8s_to_icp(fee_e8s):.8f} ICP ({fee_e8s} e8s)")
        
        result = ledger.transfer(transfer_args)
        result_value = get_result_value(result)
        
        if result_value:
            # TransferResult is a variant, could be Ok or Err
            if isinstance(result_value, dict):
                if 'Ok' in result_value:
                    block_index = result_value['Ok']
                    print(f"[+] Transfer successful! Block index: {block_index}")
                    return {'success': True, 'block_index': block_index}
                elif 'Err' in result_value:
                    error = result_value['Err']
                    print(f"[!] Transfer failed: {error}")
                    return {'success': False, 'error': error}
                else:
                    # May be directly returned dict format
                    if 'block_index' in result_value or isinstance(result_value, (int, str)):
                        print(f"[+] Transfer successful! Result: {result_value}")
                        return {'success': True, 'result': result_value}
                    else:
                        print(f"[!] Unknown return format: {result_value}")
                        return {'success': False, 'error': f'Unknown format: {result_value}'}
            elif isinstance(result_value, (int, str)):
                # Directly return block index
                print(f"[+] Transfer successful! Block index: {result_value}")
                return {'success': True, 'block_index': result_value}
            else:
                print(f"[!] Unknown return type: {type(result_value)}, value: {result_value}")
                return {'success': False, 'error': f'Unknown type: {type(result_value)}'}
        else:
            print(f"[!] Transfer returned empty result")
            return {'success': False, 'error': 'Empty result'}
            
    except Exception as e:
        handle_exception("Execute transfer", e, verbose=True)
        return {'success': False, 'error': str(e)}


def main():
    """Main function"""
    print("=" * 70)
    print("ICP Ledger Complete Interaction Example")
    print("=" * 70)
    
    # Step 1: Create Identity from PEM private key
    print_section("[1] Create Identity from PEM Private Key")
    try:
        identity = Identity.from_pem(PRIVATE_KEY_PEM)
        print(f"[+] Identity created successfully")
        print(f"    Key type: {identity.key_type}")
        print(f"    Private key (hex): {identity.privkey}")
        print(f"    Public key (hex): {identity.pubkey}")
        
        # Get Principal
        principal = identity.sender()
        print(f"    Principal: {principal.to_str()}")
        
        # Get account identifier
        account_id = principal.to_account_id()
        account_id_bytes = account_id.bytes
        print(f"    Account identifier: {account_id.to_str()}")
        print(f"    Account identifier (hex): {account_id_bytes.hex()}")
        
    except Exception as e:
        handle_exception("Create Identity", e, verbose=True)
        return
    
    # Step 2: Connect to IC mainnet
    print_section("[2] Connect to IC Mainnet")
    try:
        client = Client(url="https://ic0.app")
        agent = Agent(identity, client)
        print("[+] Connected to IC mainnet")
    except Exception as e:
        handle_exception("Network connection", e, verbose=True)
        return
    
    # Step 3: Initialize Ledger Canister
    print_section("[3] Initialize Ledger Canister")
    try:
        ledger = Ledger(agent)
        print(f"[+] Ledger Canister initialized successfully")
        print(f"    Canister ID: {LEDGER_CANISTER_ID}")
    except Exception as e:
        handle_exception("Ledger initialization", e, verbose=True)
        return
    
    # Step 4: Query account balance
    print_section("[4] Query Account Balance")
    balance_e8s = get_account_balance(ledger, account_id_bytes)
    if balance_e8s is not None:
        balance_icp = e8s_to_icp(balance_e8s)
        print(f"[+] Account balance: {balance_icp:.8f} ICP ({balance_e8s} e8s)")
    else:
        print("[!] Unable to get account balance")
        return
    
    # Step 5: Query transfer fee
    print_section("[5] Query Transfer Fee")
    fee_e8s = get_transfer_fee(ledger)
    if fee_e8s is not None:
        fee_icp = e8s_to_icp(fee_e8s)
        print(f"[+] Transfer fee: {fee_icp:.8f} ICP ({fee_e8s} e8s)")
    else:
        print("[!] Unable to get transfer fee, using default value 10000 e8s")
        fee_e8s = 10000  # Default fee
    
    # Step 6: Query token metadata
    print_section("[6] Query Token Metadata")
    try:
        # Query symbol
        symbol_result = ledger.symbol()
        symbol_dict = get_result_value(symbol_result)
        if symbol_dict:
            symbol = symbol_dict.get('symbol') or (list(symbol_dict.values())[0] if symbol_dict else None)
            if symbol:
                print(f"[+] Token symbol: {symbol}")
        
        # Query name
        name_result = ledger.name()
        name_dict = get_result_value(name_result)
        if name_dict:
            name = name_dict.get('name') or (list(name_dict.values())[0] if name_dict else None)
            if name:
                print(f"[+] Token name: {name}")
        
        # Query decimals
        decimals_result = ledger.decimals()
        decimals_dict = get_result_value(decimals_result)
        if decimals_dict:
            decimals = decimals_dict.get('decimals') or (list(decimals_dict.values())[0] if decimals_dict else None)
            if decimals is not None:
                print(f"[+] Token decimals: {decimals}")
    except Exception as e:
        handle_exception("Query token metadata", e)
    
    # Step 7: Query recent blocks (optional)
    print_section("[7] Query Recent Blocks")
    try:
        # Query last 5 blocks
        blocks_result = ledger.query_blocks({
            'start': 0,  # Start from latest block (will actually return recent blocks)
            'length': 5
        })
        blocks_dict = get_result_value(blocks_result)
        if blocks_dict:
            chain_length = blocks_dict.get('chain_length', 0)
            blocks = blocks_dict.get('blocks', [])
            first_block_index = blocks_dict.get('first_block_index', 0)
            print(f"[+] Chain length: {chain_length}")
            print(f"[+] Number of blocks returned: {len(blocks)}")
            print(f"[+] First block index: {first_block_index}")
            if blocks:
                print(f"[+] Latest block index: {first_block_index + len(blocks) - 1}")
    except Exception as e:
        handle_exception("Query blocks", e)
    
    # Step 8: Execute transfer (if balance is sufficient)
    print_section("[8] Execute Transfer Operation")
    
    if not ENABLE_TRANSFER:
        print("[*] Transfer feature is disabled (ENABLE_TRANSFER = False)")
        print("[*] Skipping transfer step")
    else:
        # Calculate available transfer amount (balance - fee)
        available_e8s = balance_e8s - fee_e8s
        
        if available_e8s <= 0:
            print(f"[!] Insufficient balance, cannot execute transfer")
            print(f"    Current balance: {e8s_to_icp(balance_e8s):.8f} ICP")
            print(f"    Required fee: {e8s_to_icp(fee_e8s):.8f} ICP")
            print(f"    Available balance: {e8s_to_icp(available_e8s):.8f} ICP")
        else:
            # Transfer amount: use half of available balance (keep some balance for subsequent operations)
            transfer_amount_e8s = available_e8s // 2
            
            # If transfer amount is too small, use minimum amount (0.0001 ICP = 10000 e8s)
            min_transfer_e8s = 10000
            if transfer_amount_e8s < min_transfer_e8s:
                transfer_amount_e8s = min_transfer_e8s
            
            # Ensure transfer amount + fee does not exceed balance
            if transfer_amount_e8s + fee_e8s > balance_e8s:
                transfer_amount_e8s = balance_e8s - fee_e8s
            
            # Target account
            if TRANSFER_MODE == 'self':
                # Transfer to self (safer, won't actually transfer money away)
                receiver_account_bytes = account_id_bytes
                print(f"[*] Transfer mode: Transfer to self (safe mode)")
            else:
                # Transfer to other account
                receiver_account_bytes = bytes.fromhex(TEST_RECEIVER_ACCOUNT_HEX)
                print(f"[*] Transfer mode: Transfer to other account")
                print(f"[!] Warning: This will execute a real transfer operation!")
            
            print(f"[*] Preparing transfer:")
            print(f"    Transfer amount: {e8s_to_icp(transfer_amount_e8s):.8f} ICP")
            print(f"    Fee: {e8s_to_icp(fee_e8s):.8f} ICP")
            print(f"    Total expense: {e8s_to_icp(transfer_amount_e8s + fee_e8s):.8f} ICP")
            print(f"    Balance after transfer: {e8s_to_icp(balance_e8s - transfer_amount_e8s - fee_e8s):.8f} ICP")
            
            # Ask for user confirmation (in actual use, can add user input confirmation)
            print(f"\n[*] Note: This will execute a real transfer operation!")
            print(f"[*] Press Ctrl+C to cancel")
            print(f"[*] Starting transfer in 5 seconds...")
            time.sleep(5)
            
            # Execute transfer
            transfer_result = transfer_icp(
                ledger,
                receiver_account_bytes,
                transfer_amount_e8s,
                fee_e8s,
                memo=0
            )
            
            if transfer_result.get('success'):
                print(f"[+] Transfer operation submitted")
                if 'block_index' in transfer_result:
                    print(f"    Block index: {transfer_result['block_index']}")
                
                # Wait a few seconds for transaction confirmation
                print(f"\n[*] Waiting 3 seconds for transaction confirmation...")
                time.sleep(3)
                
                # Step 9: Query balance again to confirm transfer
                print_section("[9] Query Balance Again to Confirm Transfer Result")
                new_balance_e8s = get_account_balance(ledger, account_id_bytes)
                if new_balance_e8s is not None:
                    new_balance_icp = e8s_to_icp(new_balance_e8s)
                    print(f"[+] New account balance: {new_balance_icp:.8f} ICP ({new_balance_e8s} e8s)")
                    
                    balance_change = balance_e8s - new_balance_e8s
                    print(f"[+] Balance change: {e8s_to_icp(balance_change):.8f} ICP ({balance_change} e8s)")
                    
                    # If transferring to self, only fee will be deducted
                    # If transferring to other account, transfer amount + fee will be deducted
                    if TRANSFER_MODE == 'self':
                        expected_change = fee_e8s  # When transferring to self, only fee
                        print(f"[*] Transferring to self: only fee will be deducted")
                    else:
                        expected_change = transfer_amount_e8s + fee_e8s  # When transferring to others, transfer amount + fee
                        print(f"[*] Transferring to others: transfer amount + fee will be deducted")
                    
                    if abs(balance_change - expected_change) < 1000:  # Allow small error
                        print(f"[+] Balance change matches expectation")
                    else:
                        print(f"[!] Balance change does not match expectation")
                        print(f"    Expected change: {e8s_to_icp(expected_change):.8f} ICP")
                        print(f"    Actual change: {e8s_to_icp(balance_change):.8f} ICP")
            else:
                print(f"[!] Transfer failed: {transfer_result.get('error', 'Unknown error')}")
    
    # Step 10: Query archive information
    print_section("[10] Query Archive Canister Information")
    try:
        archives_result = ledger.archives()
        archives_dict = get_result_value(archives_result)
        if archives_dict:
            archives_list = archives_dict.get('archives') or (list(archives_dict.values())[0] if archives_dict else None)
            if archives_list:
                print(f"[+] Found {len(archives_list)} archive Canisters")
                for i, archive in enumerate(archives_list[:3]):  # Show first 3
                    if isinstance(archive, dict):
                        canister_id = archive.get('canister_id') or (list(archive.values())[0] if archive else None)
                        if canister_id:
                            # canister_id may be Principal object or string
                            if hasattr(canister_id, 'to_str'):
                                print(f"    Archive {i+1}: {canister_id.to_str()}")
                            else:
                                print(f"    Archive {i+1}: {canister_id}")
            else:
                print("[+] No archive Canisters found")
    except Exception as e:
        handle_exception("Query archive information", e)
    
    print("\n" + "=" * 70)
    print("Example execution completed")
    print("=" * 70)


if __name__ == "__main__":
    main()
