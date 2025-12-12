import sys
import os
import unittest

# Add src directory to path
project_root = os.path.join(os.path.dirname(__file__), '..')
src_path = os.path.join(project_root, 'src')
sys.path.insert(0, src_path)

from icp_candid.did_loader import DIDLoader


class TestDIDLoader(unittest.TestCase):
    """Test suite for DIDLoader class."""

    def test_load_did_source_with_service(self):
        """Test loading a DID file with service definition."""
        did_code = """
type Profile = record {
    name: text;
    age: nat8;
    emails: vec text;
};

service : {
    get_profile : (text) -> (opt Profile) query;
    update_profile : (Profile) -> ();
}
"""
        loader = DIDLoader()
        result = loader.load_did_source(did_code)
        
        assert result is not None
        assert isinstance(result, dict)
        assert "methods" in result
        assert "arguments" in result
        
        methods = result.get("methods", {})
        assert len(methods) == 2
        assert "get_profile" in methods
        assert "update_profile" in methods

    def test_get_profile_method_signature(self):
        """Test get_profile method has correct signature."""
        did_code = """
type Profile = record {
    name: text;
    age: nat8;
    emails: vec text;
};

service : {
    get_profile : (text) -> (opt Profile) query;
}
"""
        loader = DIDLoader()
        result = loader.load_did_source(did_code)
        
        method = result["methods"]["get_profile"]
        
        # Check argument types
        assert len(method.argTypes) == 1
        assert method.argTypes[0].name == "text"
        
        # Check return types
        assert len(method.retTypes) == 1
        assert "opt" in method.retTypes[0].name.lower()
        
        # Check annotations
        assert "query" in method.annotations

    def test_update_profile_method_signature(self):
        """Test update_profile method has correct signature."""
        did_code = """
type Profile = record {
    name: text;
    age: nat8;
};

service : {
    update_profile : (Profile) -> ();
}
"""
        loader = DIDLoader()
        result = loader.load_did_source(did_code)
        
        method = result["methods"]["update_profile"]
        
        # Check argument types
        assert len(method.argTypes) == 1
        assert "record" in method.argTypes[0].name.lower()
        
        # Check return types (empty tuple)
        assert len(method.retTypes) == 0 or (len(method.retTypes) == 1 and method.retTypes[0].name == "empty")
        
        # Check annotations (update method, no query)
        assert "query" not in method.annotations

    def test_init_arguments(self):
        """Test loading DID with init arguments."""
        # [FIX] Corrected syntax: service : (args) -> { ... }
        did_code = """
service : (text, nat) -> {
    greet : (text) -> (text);
}
"""
        loader = DIDLoader()
        result = loader.load_did_source(did_code)
        
        init_args = result.get("arguments", [])
        assert len(init_args) == 2
        assert init_args[0].name == "text"
        assert init_args[1].name == "nat"

    def test_no_init_arguments(self):
        """Test loading DID without init arguments."""
        did_code = """
service : {
    greet : (text) -> (text);
}
"""
        loader = DIDLoader()
        result = loader.load_did_source(did_code)
        
        init_args = result.get("arguments", [])
        assert len(init_args) == 0

    def test_custom_type_reference(self):
        """Test loading DID with custom type references."""
        did_code = """
type User = record {
    id: nat;
    name: text;
};

service : {
    get_user : (nat) -> (opt User) query;
    create_user : (text) -> (User);
}
"""
        loader = DIDLoader()
        result = loader.load_did_source(did_code)
        
        methods = result["methods"]
        assert "get_user" in methods
        assert "create_user" in methods
        
        # Verify get_user returns optional User
        get_user_method = methods["get_user"]
        assert len(get_user_method.retTypes) == 1
        assert "opt" in get_user_method.retTypes[0].name.lower()

    def test_tuple_type_detection(self):
        """Test that tuple types are correctly detected and converted."""
        # [FIX] Corrected syntax: Tuple is record { ... }
        did_code = """
service : {
    process_pair : (record { text; nat }) -> (text);
}
"""
        loader = DIDLoader()
        result = loader.load_did_source(did_code)
        
        method = result["methods"]["process_pair"]
        assert len(method.argTypes) == 1
        # Tuple should be detected and converted
        arg_type = method.argTypes[0]
        assert "record" in arg_type.name.lower() or "tuple" in arg_type.name.lower()

    def test_multiple_methods(self):
        """Test loading DID with multiple methods."""
        did_code = """
service : {
    method1 : () -> (text);
    method2 : (nat) -> (nat);
    method3 : (text, nat) -> (bool) query;
}
"""
        loader = DIDLoader()
        result = loader.load_did_source(did_code)
        
        methods = result["methods"]
        assert len(methods) == 3
        assert "method1" in methods
        assert "method2" in methods
        assert "method3" in methods
        
        # Verify method3 is a query
        assert "query" in methods["method3"].annotations


if __name__ == '__main__':
    unittest.main()
