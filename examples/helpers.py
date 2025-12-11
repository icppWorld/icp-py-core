"""
Common helper functions for example scripts.

This module provides utilities to simplify result parsing and error handling
in example code, making examples more readable and maintainable.
"""

from typing import Any, Optional


def get_result_value(result: Any, index: int = 0) -> Optional[Any]:
    """
    Extract the value from a decoded Candid result.
    
    Agent.query() and Agent.update() return results in the format:
    [{"type": "...", "value": ...}]
    
    Args:
        result: The result from Agent.query() or Agent.update()
        index: Index of the return value to extract (default: 0)
    
    Returns:
        The extracted value, or None if the result format is unexpected
    
    Example:
        >>> result = ledger.account_balance({'account': account_blob})
        >>> balance = get_result_value(result)
        >>> if balance:
        >>>     print(f"Balance: {balance}")
    """
    if not isinstance(result, list) or len(result) <= index:
        return None
    
    item = result[index]
    if isinstance(item, dict) and 'value' in item:
        return item['value']
    
    # Fallback: return the item itself if it's not in expected format
    return item


def safe_get_nested_value(data: dict, *keys, default=None):
    """
    Safely get nested dictionary values.
    
    Args:
        data: Dictionary to search
        *keys: Keys to traverse (e.g., 'value', 'e8s')
        default: Default value if key path doesn't exist
    
    Returns:
        The nested value or default
    
    Example:
        >>> result = get_result_value(response)
        >>> e8s = safe_get_nested_value(result, 'value', 'e8s')
    """
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
            if current is None:
                return default
        else:
            return default
    return current


def print_section(title: str, width: int = 60):
    """Print a formatted section header."""
    print(f"\n{title}")
    print("-" * width)


def handle_exception(operation: str, error: Exception, verbose: bool = False):
    """
    Handle exceptions in a user-friendly way.
    
    Args:
        operation: Description of what operation failed
        error: The exception that occurred
        verbose: If True, print full traceback (default: False)
    """
    print(f"[!] {operation} failed: {error}")
    if verbose:
        import traceback
        traceback.print_exc()
