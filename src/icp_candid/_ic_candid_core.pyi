# Type stubs for Rust extension

def parse_did(did_content: str) -> str:
    """
    Parses a Candid DID string and returns a JSON string representing the AST.
    
    Args:
        did_content: The content of the .did file.
        
    Returns:
        A JSON string containing the parsed types and service definition.
        
    Raises:
        ValueError: If the DID syntax is invalid.
    """
    ...
