from icp_candid.did_loader import DIDLoader
from icp_candid import encode, decode, Types

class Canister:
    def __init__(self, agent, canister_id, candid_str=None):
        self.agent = agent
        self.canister_id = canister_id
        self.candid_str = candid_str
        self.methods = {}
        self.actor = None
        self.init_args = []  # Store init arguments (for Canister deployment)
        
        if candid_str:
            self._parse_did_with_retry(candid_str)

    def _parse_did_with_retry(self, did_content):
        """
        Parse DID content using the new DIDLoader.
        """
        self._parse_did(did_content)

    def _parse_did(self, did):
        """
        Parse DID content using DIDLoader and build service interface.
        """
        loader = DIDLoader()
        result = loader.load_did_source(did)
        
        if result is None:
            raise ValueError("DID content does not contain a service definition")
        
        # result is a dictionary format: {"arguments": [...], "methods": {...}}
        # Store init arguments (for Canister deployment)
        self.init_args = result.get("arguments", [])
        
        # methods dictionary contains method name to FuncClass mapping
        methods_dict = result.get("methods", {})
        if not methods_dict:
            raise ValueError("DID content does not contain any methods")
        
        # Store methods dictionary as actor (for backward compatibility)
        self.actor = methods_dict
        
        # Dynamically bind methods to Canister instance
        for name, method_type in methods_dict.items():
            self.methods[name] = method_type
            setattr(self, name, self._create_method(name, method_type))

    def _create_method(self, name, method_type):
        """
        Create dynamic method. method_type is a Types.Func object.
        """
        def method(*args, **kwargs):
            # 1. Get argument types and return types
            # method_type is a FuncClass object with argTypes and retTypes attributes
            arg_types = method_type.argTypes
            ret_types = method_type.retTypes
            
            # 2. Construct parameter list conforming to encode requirements
            processed_args = []
            for i, val in enumerate(args):
                if i < len(arg_types):
                    processed_args.append({'type': arg_types[i], 'value': val})
            
            # 3. Determine if it's a Query or Update call
            # annotations is a list, e.g. ['query'] or []
            annotations = method_type.annotations
            is_query = 'query' in annotations

            # 4. Execute network request using Agent's high-level query/update methods
            # These methods automatically encode args and decode return values
            if is_query:
                res = self.agent.query(
                    self.canister_id,
                    name,
                    arg=processed_args if processed_args else None,
                    return_type=ret_types
                )
            else:
                res = self.agent.update(
                    self.canister_id,
                    name,
                    arg=processed_args if processed_args else None,
                    return_type=ret_types
                )
            
            # 5. Return the result (already decoded by query/update methods)
            return res
            
        return method

    def __getattr__(self, name):
        if name in self.methods:
            # Use object.__getattribute__ to avoid infinite recursion
            return object.__getattribute__(self, name)
        raise AttributeError(f"'Canister' object has no attribute '{name}'")