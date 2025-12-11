"""
Example demonstrating query and update calls to a simple counter canister.

This example shows how to:
- Query the current counter value (query call)
- Set a new counter value (update call)
- Verify the value was set correctly using assertions

Canister ID: wcrzb-2qaaa-aaaap-qhpgq-cai
Candid Interface:
  service : {
    get : () -> (nat) query;
    set : (nat) -> (nat)
  }
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from icp_agent import Agent, Client
from icp_identity import Identity
from icp_canister import Canister

# Configuration
CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"

# Candid interface definition
COUNTER_DID = """
service : {
  get : () -> (nat) query;
  set : (nat) -> (nat)
}
"""


def main():
    """Main function demonstrating counter canister interactions."""
    print("=" * 60)
    print("Simple Counter Canister Example")
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
        return False

    # Initialize Counter canister
    try:
        counter = Canister(agent, CANISTER_ID, COUNTER_DID)
        print(f"[+] Counter canister initialized: {CANISTER_ID}")
    except Exception as e:
        print(f"[!] Failed to initialize counter canister: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test 1: Query call - Get initial value
    print("\n[Test 1] Query Call: Get Initial Counter Value")
    print("-" * 60)
    try:
        result = counter.get()
        
        # Parse result
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                initial_value = val['value']
            else:
                initial_value = val
            
            print(f"[+] Initial counter value: {initial_value}")
            
            # Assert: value should be a non-negative integer
            assert isinstance(initial_value, int), f"Expected int, got {type(initial_value)}"
            assert initial_value >= 0, f"Expected non-negative value, got {initial_value}"
            print("[✓] Assertion passed: Initial value is a valid nat")
        else:
            print(f"[!] Unexpected result format: {result}")
            return False
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test 2: Update call - Set a new value
    print("\n[Test 2] Update Call: Set Counter Value to 42")
    print("-" * 60)
    print("[!] Note: Using verify_certificate=False for testing (blst not required)")
    try:
        new_value = 42
        # Use agent.update directly to disable certificate verification for testing
        from icp_candid import Types
        result = agent.update(
            CANISTER_ID,
            "set",
            [{'type': Types.Nat, 'value': new_value}],
            return_type=[Types.Nat],
            verify_certificate=False
        )
        
        # Parse result
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                returned_value = val['value']
            else:
                returned_value = val
            
            print(f"[+] Set value: {new_value}")
            print(f"[+] Returned value: {returned_value}")
            
            # Assert: returned value should match the set value
            assert returned_value == new_value, \
                f"Expected {new_value}, got {returned_value}"
            assert isinstance(returned_value, int), \
                f"Expected int, got {type(returned_value)}"
            assert returned_value >= 0, \
                f"Expected non-negative value, got {returned_value}"
            print("[✓] Assertion passed: Set value matches returned value")
        else:
            print(f"[!] Unexpected result format: {result}")
            return False
    except Exception as e:
        print(f"[!] Update call failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test 3: Query call - Verify the value was set correctly
    print("\n[Test 3] Query Call: Verify Counter Value After Set")
    print("-" * 60)
    try:
        result = counter.get()
        
        # Parse result
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                current_value = val['value']
            else:
                current_value = val
            
            print(f"[+] Current counter value: {current_value}")
            
            # Assert: current value should match what we set
            assert current_value == new_value, \
                f"Expected {new_value}, got {current_value}"
            assert isinstance(current_value, int), \
                f"Expected int, got {type(current_value)}"
            print("[✓] Assertion passed: Current value matches set value")
        else:
            print(f"[!] Unexpected result format: {result}")
            return False
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test 4: Update call - Set another value
    print("\n[Test 4] Update Call: Set Counter Value to 100")
    print("-" * 60)
    try:
        another_value = 100
        # Use agent.update directly to disable certificate verification for testing
        from icp_candid import Types
        result = agent.update(
            CANISTER_ID,
            "set",
            [{'type': Types.Nat, 'value': another_value}],
            return_type=[Types.Nat],
            verify_certificate=False
        )
        
        # Parse result
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                returned_value = val['value']
            else:
                returned_value = val
            
            print(f"[+] Set value: {another_value}")
            print(f"[+] Returned value: {returned_value}")
            
            # Assert: returned value should match the set value
            assert returned_value == another_value, \
                f"Expected {another_value}, got {returned_value}"
            print("[✓] Assertion passed: Set value matches returned value")
        else:
            print(f"[!] Unexpected result format: {result}")
            return False
    except Exception as e:
        print(f"[!] Update call failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test 5: Query call - Final verification
    print("\n[Test 5] Query Call: Final Verification")
    print("-" * 60)
    try:
        result = counter.get()
        
        # Parse result
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                final_value = val['value']
            else:
                final_value = val
            
            print(f"[+] Final counter value: {final_value}")
            
            # Assert: final value should match the last set value
            assert final_value == another_value, \
                f"Expected {another_value}, got {final_value}"
            print("[✓] Assertion passed: Final value matches last set value")
        else:
            print(f"[!] Unexpected result format: {result}")
            return False
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test 6: Edge case - Set value to 0
    print("\n[Test 6] Update Call: Set Counter Value to 0 (Edge Case)")
    print("-" * 60)
    try:
        zero_value = 0
        # Use agent.update directly to disable certificate verification for testing
        from icp_candid import Types
        result = agent.update(
            CANISTER_ID,
            "set",
            [{'type': Types.Nat, 'value': zero_value}],
            return_type=[Types.Nat],
            verify_certificate=False
        )
        
        # Parse result
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                returned_value = val['value']
            else:
                returned_value = val
            
            print(f"[+] Set value: {zero_value}")
            print(f"[+] Returned value: {returned_value}")
            
            # Assert: returned value should be 0
            assert returned_value == zero_value, \
                f"Expected {zero_value}, got {returned_value}"
            
            # Verify with query
            query_result = counter.get()
            if isinstance(query_result, list) and len(query_result) > 0:
                query_val = query_result[0]
                if isinstance(query_val, dict) and 'value' in query_val:
                    query_value = query_val['value']
                else:
                    query_value = query_val
                
                assert query_value == zero_value, \
                    f"Expected {zero_value}, got {query_value}"
                print("[✓] Assertion passed: Zero value set and verified correctly")
        else:
            print(f"[!] Unexpected result format: {result}")
            return False
    except Exception as e:
        print(f"[!] Update call failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print("\n" + "=" * 60)
    print("All tests passed successfully!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
