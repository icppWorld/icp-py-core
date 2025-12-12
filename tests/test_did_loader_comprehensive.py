import unittest
import sys
import os
import json
from unittest.mock import patch

# Add src directory to path
project_root = os.path.join(os.path.dirname(__file__), '..')
src_path = os.path.join(project_root, 'src')
sys.path.insert(0, src_path)

# Import modules under test
from icp_candid.did_loader import DIDLoader
from icp_candid.candid import RecordClass, RecClass, FuncClass


class TestDIDLoader(unittest.TestCase):

    def setUp(self):
        self.loader = DIDLoader()

    @patch('icp_candid.did_loader.ic_candid_parser')
    def test_primitive_parsing(self, mock_parser):
        """Test loading of primitive types"""
        # [Actual Format] Use actual Rust parser format: {"type": "Prim", "value": "text"}
        mock_json = json.dumps({
            "env": [],
            "actor": {
                "methods": [{
                    "name": "greet",
                    "args": [{"type": "Prim", "value": "text"}],
                    "rets": [{"type": "Prim", "value": "bool"}],
                    "modes": ["query"]
                }]
            }
        })
        mock_parser.parse_did.return_value = mock_json

        result = self.loader.load_did_source("service : { ... }")

        methods = result["methods"]
        self.assertIn("greet", methods)

        func = methods["greet"]
        # did_loader returns Types.Func, which is a FuncClass instance
        self.assertIsInstance(func, FuncClass)
        self.assertEqual(len(func.args), 1)
        self.assertEqual(len(func.rets), 1)
        self.assertEqual(func.modes, ["query"])

    @patch('icp_candid.did_loader.ic_candid_parser')
    def test_record_parsing(self, mock_parser):
        """Test Record type and field conversion"""
        # [Actual Format] Use actual Rust parser format
        mock_json = json.dumps({
            "env": [
                {
                    "name": "User",
                    "datatype": {
                        "type": "Record",
                        "value": [
                            ["name", {"type": "Prim", "value": "text"}],
                            ["age", {"type": "Prim", "value": "nat8"}]
                        ]
                    }
                }
            ],
            "actor": None
        })
        mock_parser.parse_did.return_value = mock_json

        self.loader.load_did_source("...")

        user_type = self.loader.type_env["User"]
        self.assertIsInstance(user_type, RecClass)

        # Unpack RecClass to check internal Record
        record = user_type.get_type()
        self.assertIsInstance(record, RecordClass)

        # Verify field existence (needs hash lookup or internal map verification)
        # Since RecordClass internal keys are hashed, we verify indirectly via encodeValue
        test_val = {"name": "Alice", "age": 20}
        try:
            record.encodeValue(test_val)
        except Exception as e:
            self.fail(f"Failed to encode record based on DID definition: {e}")

    @patch('icp_candid.did_loader.ic_candid_parser')
    def test_recursive_type(self, mock_parser):
        """Test recursive type construction (List)"""
        # [Actual Format] Use actual Rust parser format
        mock_json = json.dumps({
            "env": [
                {
                    "name": "List",
                    "datatype": {
                        "type": "Record",
                        "value": [
                            ["head", {"type": "Prim", "value": "int"}],
                            ["tail", {"type": "Opt", "value": {"type": "Id", "value": "List"}}]
                        ]
                    }
                }
            ],
            "actor": None
        })
        mock_parser.parse_did.return_value = mock_json

        self.loader.load_did_source("...")

        list_type = self.loader.type_env["List"]
        self.assertIsInstance(list_type, RecClass)

        # Verify recursive reference
        # List -> Record -> Opt -> Id(List)
        record = list_type.get_type()
        # Find tail field
        # Note: Record internal fields are stored by hash, simplified verification logic here
        # As long as covariant validation of recursive data structure succeeds, construction is successful

        recursive_data = {"head": 1, "tail": [{"head": 2, "tail": []}]}
        self.assertTrue(list_type.covariant(recursive_data))

    @patch('icp_candid.did_loader.ic_candid_parser')
    def test_tuple_handling(self, mock_parser):
        """Test Tuple recognition logic (numeric key Record)"""
        # [Actual Format] Use actual Rust parser format: {"type": "Record", "value": [["key", type], ...]}
        mock_json = json.dumps({
            "env": [
                {
                    "name": "Pair",
                    "datatype": {
                        "type": "Record",
                        "value": [
                            ["0", {"type": "Prim", "value": "nat"}],
                            ["1", {"type": "Prim", "value": "text"}]
                        ]
                    }
                }
            ],
            "actor": None
        })
        mock_parser.parse_did.return_value = mock_json

        self.loader.load_did_source("...")
        pair_type = self.loader.type_env["Pair"].get_type()

        # Verify if recognized as Tuple
        self.assertTrue(pair_type.tryAsTuple())

        # Verify if can handle list input (via encodeValue, which supports list input)
        try:
            pair_type.encodeValue([10, "hello"])
        except Exception as e:
            self.fail(f"Failed to encode tuple from list: {e}")
        
        # Verify if can handle dict input (using numeric keys)
        self.assertTrue(pair_type.covariant({"0": 10, "1": "hello"}))


if __name__ == '__main__':
    unittest.main()
