import json

try:

    from . import _ic_candid_core as ic_candid_parser

except ImportError:

    try:

        import ic_candid_parser

    except ImportError:

        pass 

from .candid import Types

class DIDLoader:

    def __init__(self):

        self.type_env = {}

    def load_did_source(self, did_content: str):

        if 'ic_candid_parser' not in globals() and 'ic_candid_parser' not in locals():

             raise ImportError("Rust extension 'ic_candid_parser' is required. Run 'maturin develop'.")

             

        try:

            json_str = ic_candid_parser.parse_did(did_content)

        except ValueError as e:

            raise ValueError(f"DID Parse Error: {e}")

            

        data = json.loads(json_str)

        self.type_env = {}

        

        # 1. Pre-declare Recursive Types

        if 'env' in data:

            for entry in data['env']:

                self.type_env[entry['name']] = Types.Rec()

        

        # 2. Fill Types

        if 'env' in data:

            for entry in data['env']:

                # [Robustness] Support 'def' (New Rust), 'datatype' (Old Rust), or 'type'

                def_node = entry.get('def') or entry.get('datatype') or entry.get('type')

                if def_node:

                    self.type_env[entry['name']].fill(self._parse_json_type(def_node))

        init_args = []

        actor_data = data.get('actor') or {}

        if 'init' in actor_data and actor_data['init']:

            init_args = [self._parse_json_type(t) for t in actor_data['init']]

             

        methods = {}

        for m in actor_data.get('methods', []):

            methods[m['name']] = Types.Func(

                [self._parse_json_type(t) for t in m['args']],

                [self._parse_json_type(t) for t in m['rets']],

                m['modes']

            )

             

        return {

            "arguments": init_args,

            "methods": methods

        }

    def _parse_json_type(self, t_node):

        # Handle string primitives (legacy format)
        if isinstance(t_node, str): return self._prim(t_node)

        # [Compatibility] Handle Rust parser output format: {"type": "Prim", "value": "text"}
        # This is the CURRENT format returned by the Rust extension
        if isinstance(t_node, dict) and 'type' in t_node and 'value' in t_node:
            tag = t_node['type']
            val = t_node['value']
        else:
            # Handle legacy format: {"Prim": "text"}
            tag = list(t_node.keys())[0]
            val = t_node[tag]

        if tag == 'Prim': return self._prim(val)

        

        elif tag == 'Opt': return Types.Opt(self._parse_json_type(val))

        elif tag == 'Vec': return Types.Vec(self._parse_json_type(val))

        elif tag == 'Record':
            fields = {}
            
            # [Compatibility] Handle Rust parser format: {"type": "Record", "value": [["key", type], ...]}
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, list) and len(item) == 2:
                        k, v = item
                        # Keep string keys as strings to support tryAsTuple() detection
                        key = k  # Keep original format for tuple detection
                        fields[key] = self._parse_json_type(v)
            else:
                # Handle legacy format: {"Record": {"key": type, ...}}
                for k, v in val.items():
                    # Keep string numeric keys as strings for tuple detection
                    key = k  # Keep original format
                    fields[key] = self._parse_json_type(v)

            return Types.Record(fields)

        elif tag == 'Variant':
            fields = {}
            
            # [Compatibility] Handle Rust parser format: {"type": "Variant", "value": [["key", type], ...]}
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, list) and len(item) == 2:
                        k, v = item
                        key = int(k) if isinstance(k, str) and k.isdigit() else k
                        fields[key] = (self._parse_json_type(v) if v else None)
            else:
                # Handle legacy format: {"Variant": {"key": type, ...}}
                for k, v in val.items():
                    key = int(k) if k.isdigit() else k
                    fields[key] = (self._parse_json_type(v) if v else None)

            return Types.Variant(fields)

        elif tag == 'Id':

            return self.type_env.get(val) or Types.Rec()

        elif tag == 'Principal': return Types.Principal

        elif tag == 'Func':

             return Types.Func(

                 [self._parse_json_type(x) for x in val['args']],

                 [self._parse_json_type(x) for x in val['rets']],

                 val['modes']

             )

        elif tag == 'Service': return Types.Service({})

        # Fallback for unknown tags (likely primitive or error)
        return self._prim(tag)

    def _prim(self, t):

        m = {'nat': Types.Nat, 'int': Types.Int, 'text': Types.Text, 'bool': Types.Bool, 'null': Types.Null, 'float64': Types.Float64, 'float32': Types.Float32, 'nat8': Types.Nat8, 'nat16': Types.Nat16, 'nat32': Types.Nat32, 'nat64': Types.Nat64, 'int8': Types.Int8, 'int16': Types.Int16, 'int32': Types.Int32, 'int64': Types.Int64, 'principal': Types.Principal, 'empty': Types.Empty, 'reserved': Types.Reserved}

        return m.get(t.lower(), Types.Null)
