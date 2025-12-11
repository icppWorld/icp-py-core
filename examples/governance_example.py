"""
Example demonstrating query and update calls to the ICP Governance canister.

This example shows how to:
- Query neuron information (query call)
- Query proposal information (query call)
- Query known neurons (query call)
- Query network economics (query call)
- Manage neuron (update call - requires authenticated identity)
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from icp_agent import Agent, Client
from icp_identity import Identity
from icp_canister import Governance

# Configuration
GOVERNANCE_CANISTER_ID = "rrkah-fqaaa-aaaaa-aaaaq-cai"  # NNS Governance mainnet


def main():
    """Main function demonstrating governance interactions."""
    print("=" * 60)
    print("ICP Governance Example")
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

    # Initialize Governance canister
    try:
        governance = Governance(agent)
        print("[+] Governance canister initialized")
    except Exception as e:
        print(f"[!] Failed to initialize governance: {e}")
        import traceback
        traceback.print_exc()
        return

    # Example 1: Query call - Get build metadata
    print("\n[1] Query Call: Get Build Metadata")
    print("-" * 60)
    try:
        result = governance.get_build_metadata()
        if isinstance(result, list) and len(result) > 0:
            metadata = result[0]
            print(f"[+] Build metadata: {metadata}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 2: Query call - List known neurons
    print("\n[2] Query Call: List Known Neurons")
    print("-" * 60)
    try:
        result = governance.list_known_neurons()
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                response_dict = val['value']
                known_neurons = response_dict.get('known_neurons') or (list(response_dict.values())[0] if response_dict else None)
                if known_neurons:
                    print(f"[+] Found {len(known_neurons)} known neurons")
                    for i, neuron in enumerate(known_neurons[:5]):  # Show first 5
                        if isinstance(neuron, dict):
                            neuron_id = neuron.get('id', {})
                            if isinstance(neuron_id, dict):
                                nid = neuron_id.get('id') or (list(neuron_id.values())[0] if neuron_id else None)
                                if nid is not None:
                                    known_data = neuron.get('known_neuron_data', {})
                                    name = known_data.get('name') if isinstance(known_data, dict) else None
                                    print(f"    Neuron {i+1}: ID={nid}, Name={name or 'N/A'}")
                else:
                    print("[+] No known neurons found")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 3: Query call - Get network economics parameters
    print("\n[3] Query Call: Get Network Economics Parameters")
    print("-" * 60)
    try:
        result = governance.get_network_economics_parameters()
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                economics = val['value']
                min_stake = economics.get('neuron_minimum_stake_e8s') or (list(economics.values())[0] if economics else None)
                if min_stake is not None:
                    min_stake_icp = min_stake / 100_000_000.0
                    print(f"[+] Minimum neuron stake: {min_stake_icp:.8f} ICP")
                    print(f"[+] Transaction fee: {economics.get('transaction_fee_e8s', 0) / 100_000_000.0:.8f} ICP")
                    print(f"[+] Reject cost: {economics.get('reject_cost_e8s', 0) / 100_000_000.0:.8f} ICP")
                else:
                    print(f"[!] Unable to extract economics data: {economics}")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 4: Query call - List node providers
    print("\n[4] Query Call: List Node Providers")
    print("-" * 60)
    try:
        result = governance.list_node_providers()
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                response_dict = val['value']
                node_providers = response_dict.get('node_providers') or (list(response_dict.values())[0] if response_dict else None)
                if node_providers:
                    print(f"[+] Found {len(node_providers)} node providers")
                    for i, provider in enumerate(node_providers[:3]):  # Show first 3
                        if isinstance(provider, dict):
                            provider_id = provider.get('id') or (list(provider.values())[0] if provider else None)
                            if provider_id:
                                print(f"    Provider {i+1}: {provider_id}")
                else:
                    print("[+] No node providers found")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 5: Query call - Get pending proposals
    print("\n[5] Query Call: Get Pending Proposals")
    print("-" * 60)
    try:
        result = governance.get_pending_proposals(None)
        if isinstance(result, list) and len(result) > 0:
            proposals = result[0] if isinstance(result[0], list) else result
            if isinstance(proposals, list):
                print(f"[+] Found {len(proposals)} pending proposals")
                for i, proposal in enumerate(proposals[:3]):  # Show first 3
                    if isinstance(proposal, dict):
                        proposal_id = proposal.get('id', {})
                        if isinstance(proposal_id, dict):
                            pid = proposal_id.get('id') or (list(proposal_id.values())[0] if proposal_id else None)
                            status = proposal.get('status')
                            topic = proposal.get('topic')
                            print(f"    Proposal {i+1}: ID={pid}, Status={status}, Topic={topic}")
            else:
                print(f"[!] Unexpected proposals format: {proposals}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Example 6: Query call - Get latest reward event
    print("\n[6] Query Call: Get Latest Reward Event")
    print("-" * 60)
    try:
        result = governance.get_latest_reward_event()
        if isinstance(result, list) and len(result) > 0:
            val = result[0]
            if isinstance(val, dict) and 'value' in val:
                event = val['value']
                distributed = event.get('distributed_e8s_equivalent') or (list(event.values())[0] if event else None)
                if distributed is not None:
                    distributed_icp = distributed / 100_000_000.0
                    print(f"[+] Latest reward event distributed: {distributed_icp:.8f} ICP")
                    print(f"[+] Day after genesis: {event.get('day_after_genesis', 'N/A')}")
                else:
                    print(f"[!] Unable to extract reward event data: {event}")
            else:
                print(f"[!] Unexpected result format: {result}")
        else:
            print(f"[!] Unexpected result: {result}")
    except Exception as e:
        print(f"[!] Query failed: {e}")
        import traceback
        traceback.print_exc()

    # Note: Update calls (like manage_neuron) require authenticated identity
    # They are not demonstrated here to avoid accidental operations
    print("\n" + "=" * 60)
    print("Note: Update calls (e.g., manage_neuron, register_vote) require")
    print("authenticated identity and proper permissions. They are not")
    print("demonstrated here to avoid accidental operations.")
    print("=" * 60)


if __name__ == "__main__":
    main()
