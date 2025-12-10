from icp_identity import Identity


class TestIdentity:

    def test_ed25519_privatekey(self):
        iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        assert iden.key_type == 'ed25519'
        assert iden.pubkey == 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf'

    def test_ed25519_frompem(self):
        pem = """
        -----BEGIN PRIVATE KEY-----
        MFMCAQEwBQYDK2VwBCIEIGQqNAZlORmn1k4QrYz1FvO4fOQowS3GXQMqRKDzmx9P
        oSMDIQCrO5iGM5hnLWrHavywoXekAoXPpYRuB0Dr6DjZF6FZkg==
        -----END PRIVATE KEY-----"""
        iden = Identity.from_pem(pem)
        assert iden.key_type == 'ed25519'
        assert iden.privkey == '642a3406653919a7d64e10ad8cf516f3b87ce428c12dc65d032a44a0f39b1f4f'
        assert iden.pubkey == 'ab3b98863398672d6ac76afcb0a177a40285cfa5846e0740ebe838d917a15992'

    def test_ed25519_from_seed_slip10(self):
        # SLIP-0010 with ICP path m/44'/223'/0'/0'/0'
        mnemonic = 'fence dragon soft spoon embrace bronze regular hawk more remind detect slam'
        iden = Identity.from_seed(mnemonic)
        assert iden.key_type == 'ed25519'
        # Correct SLIP-0010 (all-hardened) output for the path above:
        assert iden.privkey == '8cb300e3b7d3d5181bda96437a6a5e6d8cdfc0eba02497e7bb6a3e320f5736c9'

    def test_secp256k1_frompem(self):
        """Test loading secp256k1 identity from PEM format."""
        pem = """
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILl8JwS6fClkxZWDjgVbXtS/XI6e/aUo0xykFA1BNJEsoAcGBSuBBAAK
oUQDQgAEy2QTwzNvyNP6cva4XVs0VV09m5ccMwrPTBMVPIIMR6B9uznY+8RdFze2
dUjS98An2Ge7Y5ydwjDH1QY1cOfH3w==
-----END EC PRIVATE KEY-----"""
        iden = Identity.from_pem(pem)
        assert iden.key_type == 'secp256k1'
        # Verify that we can get the private and public keys
        assert len(iden.privkey) == 64  # 32 bytes = 64 hex chars
        assert len(iden.pubkey) == 128  # 64 bytes (x||y coordinates, no 0x04 prefix) = 128 hex chars
        assert iden.der_pubkey is not None
        assert len(iden.der_pubkey) > 0

    def test_secp256k1_sign_verify(self):
        """Test secp256k1 signing and verification with 64-byte raw signature format."""
        pem = """
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILl8JwS6fClkxZWDjgVbXtS/XI6e/aUo0xykFA1BNJEsoAcGBSuBBAAK
oUQDQgAEy2QTwzNvyNP6cva4XVs0VV09m5ccMwrPTBMVPIIMR6B9uznY+8RdFze2
dUjS98An2Ge7Y5ydwjDH1QY1cOfH3w==
-----END EC PRIVATE KEY-----"""
        iden = Identity.from_pem(pem)
        assert iden.key_type == 'secp256k1'

        # Test message
        message = b"Hello, Internet Computer!"
        
        # Sign the message
        der_pubkey, signature = iden.sign(message)
        assert der_pubkey is not None
        assert signature is not None
        
        # Verify signature format: should be 64 bytes (r||s format, not DER)
        assert len(signature) == 64, f"Expected 64-byte signature, got {len(signature)} bytes"
        
        # Verify the signature
        assert iden.verify(message, signature) is True
        
        # Test with wrong message (should fail)
        wrong_message = b"Wrong message"
        assert iden.verify(wrong_message, signature) is False
        
        # Test with wrong signature (should fail)
        wrong_sig = bytes([0] * 64)
        assert iden.verify(message, wrong_sig) is False

    def test_secp256k1_signature_format(self):
        """Test that secp256k1 signatures are in 64-byte raw r||s format, not DER."""
        pem = """
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILl8JwS6fClkxZWDjgVbXtS/XI6e/aUo0xykFA1BNJEsoAcGBSuBBAAK
oUQDQgAEy2QTwzNvyNP6cva4XVs0VV09m5ccMwrPTBMVPIIMR6B9uznY+8RdFze2
dUjS98An2Ge7Y5ydwjDH1QY1cOfH3w==
-----END EC PRIVATE KEY-----"""
        iden = Identity.from_pem(pem)
        
        # Sign multiple messages to ensure consistent format
        messages = [
            b"test message 1",
            b"test message 2",
            b"",
            b"a" * 100,
        ]
        
        for msg in messages:
            _, sig = iden.sign(msg)
            # Verify signature is exactly 64 bytes (32 bytes r + 32 bytes s)
            assert len(sig) == 64, f"Signature for message '{msg[:20]}...' should be 64 bytes, got {len(sig)}"
            # Verify it's not DER format (DER would start with 0x30)
            assert sig[0] != 0x30, "Signature appears to be DER-encoded, expected raw r||s format"
            # Verify signature can be verified
            assert iden.verify(msg, sig) is True

    def test_secp256k1_principal(self):
        """Test that secp256k1 identity generates the correct self-authenticating principal."""
        pem = """
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILl8JwS6fClkxZWDjgVbXtS/XI6e/aUo0xykFA1BNJEsoAcGBSuBBAAK
oUQDQgAEy2QTwzNvyNP6cva4XVs0VV09m5ccMwrPTBMVPIIMR6B9uznY+8RdFze2
dUjS98An2Ge7Y5ydwjDH1QY1cOfH3w==
-----END EC PRIVATE KEY-----"""
        iden = Identity.from_pem(pem)
        assert iden.key_type == 'secp256k1'
        
        # Get the principal from the identity
        principal = iden.sender()
        principal_str = principal.to_str()
        
        # Verify it matches the expected principal
        expected_principal = 'ci3mc-ql64m-v6wnr-ovogw-dokkm-tsoxn-5egku-fkftb-6xadu-xddad-sae'
        assert principal_str == expected_principal, \
            f"Expected principal '{expected_principal}', got '{principal_str}'"
        
        # Verify the principal is self-authenticating type
        assert principal.bytes[-1] == 0x02  # SelfAuthenticating = 2

    def test_secp256k1_der_pubkey_principal(self):
        """Test that secp256k1 DER public key generates the correct principal."""
        pem = """
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILl8JwS6fClkxZWDjgVbXtS/XI6e/aUo0xykFA1BNJEsoAcGBSuBBAAK
oUQDQgAEy2QTwzNvyNP6cva4XVs0VV09m5ccMwrPTBMVPIIMR6B9uznY+8RdFze2
dUjS98An2Ge7Y5ydwjDH1QY1cOfH3w==
-----END EC PRIVATE KEY-----"""
        iden = Identity.from_pem(pem)
        
        # Get DER public key and create principal from it
        from icp_principal import Principal
        der_pubkey = iden.der_pubkey
        principal_from_der = Principal.self_authenticating(der_pubkey)
        principal_str = principal_from_der.to_str()
        
        # Verify it matches the expected principal
        expected_principal = 'ci3mc-ql64m-v6wnr-ovogw-dokkm-tsoxn-5egku-fkftb-6xadu-xddad-sae'
        assert principal_str == expected_principal, \
            f"Expected principal '{expected_principal}', got '{principal_str}'"
        
        # Verify it's the same as identity.sender()
        assert principal_from_der == iden.sender()

    def test_secp256k1_sign_with_principal(self):
        """Test signing with secp256k1 identity and verify the principal in the signature."""
        pem = """
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILl8JwS6fClkxZWDjgVbXtS/XI6e/aUo0xykFA1BNJEsoAcGBSuBBAAK
oUQDQgAEy2QTwzNvyNP6cva4XVs0VV09m5ccMwrPTBMVPIIMR6B9uznY+8RdFze2
dUjS98An2Ge7Y5ydwjDH1QY1cOfH3w==
-----END EC PRIVATE KEY-----"""
        iden = Identity.from_pem(pem)
        
        # Verify the principal
        expected_principal = 'ci3mc-ql64m-v6wnr-ovogw-dokkm-tsoxn-5egku-fkftb-6xadu-xddad-sae'
        assert iden.sender().to_str() == expected_principal
        
        # Sign a message
        message = b"Test message for principal verification"
        der_pubkey, signature = iden.sign(message)
        
        # Verify signature format
        assert len(signature) == 64
        assert len(der_pubkey) > 0
        
        # Verify the signature
        assert iden.verify(message, signature) is True
        
        # Verify that the DER pubkey can be used to create the same principal
        from icp_principal import Principal
        principal_from_sig = Principal.self_authenticating(der_pubkey)
        assert principal_from_sig.to_str() == expected_principal