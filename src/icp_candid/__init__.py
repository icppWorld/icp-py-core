from .candid import encode, decode, Types, TypeTable

# Lazy loading wrapper for DIDLoader to avoid ImportErrors

# if the underlying rust extension is missing.

class DIDLoader:

    def __new__(cls, *args, **kwargs):

        try:

            from .did_loader import DIDLoader as _RealLoader

        except ImportError:

            raise ImportError("The 'ic_candid_parser' extension is required to use DIDLoader. Please install it via pip.")

        return _RealLoader(*args, **kwargs)

__all__ = ["encode", "decode", "Types", "TypeTable", "DIDLoader"]
