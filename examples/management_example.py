"""
Example demonstrating usage of the ICP Management canister.

This example shows how to use management canister methods:
- Query canister status
- Create canister (requires cycles)
- Update canister settings (requires controller permissions)
- Install code (requires controller permissions)
- Start/Stop canister
- Delete canister

Note: All management canister operations are update calls and require
proper authentication and permissions. They are not executed here to
avoid accidental operations.
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from icp_agent import Agent, Client
from icp_identity import Identity
from icp_canister import Management
from helpers import print_section, handle_exception

# Configuration
MANAGEMENT_CANISTER_ID = "aaaaa-aa"  # Management canister (system canister)


def main():
    """Main function demonstrating management canister usage."""
    print("=" * 60)
    print("ICP Management Canister Example")
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

    # Initialize Management canister
    try:
        management = Management(agent)
        print("[+] Management canister initialized")
    except Exception as e:
        handle_exception("Management canister initialization", e)
        return

    # Example 1: Canister status
    print_section("[1] Canister Status")
    print("[!] Note: canister_status is an update call (not query)")
    print("    It requires controller permissions and a valid canister ID.")
    print("    Example usage:")
    print("    ```python")
    print("    result = management.canister_status({'canister_id': principal})")
    print("    ```")
    
    # Example 2: Create canister
    print_section("[2] Create Canister")
    print("[!] Note: create_canister is an update call that requires cycles.")
    print("    Example usage:")
    print("    ```python")
    print("    result = management.create_canister({'settings': None})")
    print("    ```")
    print("    This will create a new canister and return its ID.")
    
    # Example 3: Update settings
    print_section("[3] Update Canister Settings")
    print("[!] Note: update_settings is an update call that requires")
    print("    controller permissions for the target canister.")
    print("    Example usage:")
    print("    ```python")
    print("    settings = {")
    print("        'controllers': [principal1, principal2],")
    print("        'compute_allocation': None,")
    print("        'memory_allocation': None,")
    print("        'freezing_threshold': None")
    print("    }")
    print("    management.update_settings({")
    print("        'canister_id': target_canister_id,")
    print("        'settings': settings")
    print("    })")
    print("    ```")
    
    # Example 4: Install code
    print_section("[4] Install Code")
    print("[!] Note: install_code is an update call that requires")
    print("    controller permissions and a WASM module.")
    print("    Example usage:")
    print("    ```python")
    print("    with open('canister.wasm', 'rb') as f:")
    print("        wasm_module = f.read()")
    print("    management.install_code({")
    print("        'mode': {'install': None},")
    print("        'canister_id': target_canister_id,")
    print("        'wasm_module': wasm_module,")
    print("        'arg': b''")
    print("    })")
    print("    ```")
    
    # Example 5: Start/Stop canister
    print_section("[5] Start/Stop Canister")
    print("[!] Note: start_canister and stop_canister are update calls.")
    print("    Example usage:")
    print("    ```python")
    print("    # Start canister")
    print("    management.start_canister({'canister_id': target_canister_id})")
    print("    ")
    print("    # Stop canister")
    print("    management.stop_canister({'canister_id': target_canister_id})")
    print("    ```")
    
    # Example 6: Delete canister
    print_section("[6] Delete Canister")
    print("[!] Note: delete_canister is an update call that requires")
    print("    the canister to be stopped and have no cycles.")
    print("    Example usage:")
    print("    ```python")
    print("    management.delete_canister({'canister_id': target_canister_id})")
    print("    ```")
    
    print("\n" + "=" * 60)
    print("Note: All management canister operations are update calls")
    print("and require proper authentication and permissions.")
    print("They are not executed here to avoid accidental operations.")
    print("=" * 60)


if __name__ == "__main__":
    main()
