"""
Example demonstrating query calls to the ICP Governance canister.

This example shows how to:
- Query build metadata
- Query known neurons
- Query network economics parameters
- Query node providers
- Query pending proposals
- Query latest reward event

Note: Update calls (e.g., manage_neuron, register_vote) require
authenticated identity and proper permissions. They are not demonstrated here.
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from icp_agent import Agent, Client
from icp_identity import Identity
from icp_canister import Governance
from helpers import get_result_value, print_section, handle_exception

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
        handle_exception("Network connection", e)
        return

    # Initialize Governance canister
    try:
        governance = Governance(agent)
        print("[+] Governance canister initialized")
    except Exception as e:
        handle_exception("Governance initialization", e)
        return

    # Example 1: Query build metadata
    print_section("[1] Query Call: Get Build Metadata")
    try:
        result = governance.get_build_metadata()
        metadata = get_result_value(result)
        if metadata is not None:
            print(f"[+] Build metadata: {metadata}")
    except Exception as e:
        handle_exception("Query build metadata", e)

    # Example 2: Query known neurons
    print_section("[2] Query Call: List Known Neurons")
    try:
        result = governance.list_known_neurons()
        response_dict = get_result_value(result)
        if response_dict:
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
    except Exception as e:
        handle_exception("Query known neurons", e)

    # Example 3: Query network economics parameters
    print_section("[3] Query Call: Get Network Economics Parameters")
    try:
        result = governance.get_network_economics_parameters()
        economics = get_result_value(result)
        if economics:
            min_stake = economics.get('neuron_minimum_stake_e8s') or (list(economics.values())[0] if economics else None)
            if min_stake is not None:
                min_stake_icp = min_stake / 100_000_000.0
                print(f"[+] Minimum neuron stake: {min_stake_icp:.8f} ICP")
                print(f"[+] Transaction fee: {economics.get('transaction_fee_e8s', 0) / 100_000_000.0:.8f} ICP")
                print(f"[+] Reject cost: {economics.get('reject_cost_e8s', 0) / 100_000_000.0:.8f} ICP")
    except Exception as e:
        handle_exception("Query network economics", e)

    # Example 4: Query node providers
    print_section("[4] Query Call: List Node Providers")
    try:
        result = governance.list_node_providers()
        response_dict = get_result_value(result)
        if response_dict:
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
    except Exception as e:
        handle_exception("Query node providers", e)

    # Example 5: Query pending proposals
    print_section("[5] Query Call: Get Pending Proposals")
    try:
        result = governance.get_pending_proposals(None)
        # Handle case where result might be a list directly or wrapped
        if isinstance(result, list) and len(result) > 0:
            proposals = result[0] if isinstance(result[0], list) else get_result_value(result)
        else:
            proposals = get_result_value(result)
        
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
    except Exception as e:
        handle_exception("Query pending proposals", e)

    # Example 6: Query latest reward event
    print_section("[6] Query Call: Get Latest Reward Event")
    try:
        result = governance.get_latest_reward_event()
        event = get_result_value(result)
        if event:
            distributed = event.get('distributed_e8s_equivalent') or (list(event.values())[0] if event else None)
            if distributed is not None:
                distributed_icp = distributed / 100_000_000.0
                print(f"[+] Latest reward event distributed: {distributed_icp:.8f} ICP")
                print(f"[+] Day after genesis: {event.get('day_after_genesis', 'N/A')}")
    except Exception as e:
        handle_exception("Query latest reward event", e)

    print("\n" + "=" * 60)
    print("Note: Update calls (e.g., manage_neuron, register_vote) require")
    print("authenticated identity and proper permissions. They are not")
    print("demonstrated here to avoid accidental operations.")
    print("=" * 60)


if __name__ == "__main__":
    main()
