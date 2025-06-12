import pytest
import asyncio
import hashlib
from hypothesis import given, strategies as st, settings, assume
from hypothesis.strategies import composite
import base64

# Custom strategies for Brunnen-G data types
@composite
def tpm_pubkey_strategy(draw):
    """Generate valid TPM public keys (DER format in hex)"""
    # TPM RSA keys are typically 256-512 bytes in DER format
    key_size = draw(st.integers(min_value=256, max_value=512))
    key_bytes = draw(st.binary(min_size=key_size, max_size=key_size))
    return key_bytes.hex()

@composite
def dilithium_signature_strategy(draw):
    """Generate valid Dilithium signatures"""
    # Dilithium3 signatures are 3293 bytes
    sig_bytes = draw(st.binary(min_size=3293, max_size=3293))
    return base64.b64encode(sig_bytes).decode()

@composite
def emercoin_signature_strategy(draw):
    """Generate valid Emercoin signatures"""
    # Bitcoin-style signatures are ~65 bytes
    sig_bytes = draw(st.binary(min_size=64, max_size=72))
    return base64.b64encode(sig_bytes).decode()

@composite
def yubikey_cert_strategy(draw):
    """Generate valid YubiKey certificate data"""
    cert_size = draw(st.integers(min_value=500, max_value=2000))
    cert_bytes = draw(st.binary(min_size=cert_size, max_size=cert_size))
    return cert_bytes.hex()

@composite
def identity_components_strategy(draw):
    """Generate complete identity components"""
    return {
        'tpm_pubkey': draw(tpm_pubkey_strategy()),
        'dilithium_sig': draw(dilithium_signature_strategy()),
        'emercoin_sig': draw(emercoin_signature_strategy()),
        'yubikey_cert': draw(yubikey_cert_strategy()),
        'tpm_nonce': draw(st.binary(min_size=32, max_size=32)).hex(),
        'device_name': draw(st.one_of(st.none(), st.text(min_size=1, max_size=50))),
        'ygg_pubkey': draw(st.one_of(st.none(), st.binary(min_size=32, max_size=32).map(lambda b: b.hex()))),
        'include_ygg': draw(st.booleans())
    }

# Identity computation functions
async def compute_hash(data: bytes) -> str:
    """Async wrapper for SHA256 hashing"""
    return hashlib.sha256(data).hexdigest()

async def compute_identity_v2(components: dict) -> str:
    """Compute Version 2 identity hash"""
    # Base components
    tpm_hash = await compute_hash(bytes.fromhex(components['tpm_pubkey']))
    
    # Dilithium signature of Emercoin signature
    emercoin_sig_hash = await compute_hash(base64.b64decode(components['emercoin_sig']))
    dilithium_data = await compute_hash(
        base64.b64decode(components['dilithium_sig']) + bytes.fromhex(emercoin_sig_hash)
    )
    
    # Combine base components
    base = bytes.fromhex(tpm_hash) + bytes.fromhex(dilithium_data)
    
    # Add optional device name
    if components.get('device_name'):
        device_hash = await compute_hash(components['device_name'].encode())
        base += bytes.fromhex(device_hash)
    
    # Add YubiKey
    yubikey_hash = await compute_hash(bytes.fromhex(components['yubikey_cert']))
    base += bytes.fromhex(yubikey_hash)
    
    # Add optional Yggdrasil
    if components.get('include_ygg') and components.get('ygg_pubkey'):
        ygg_hash = await compute_hash(bytes.fromhex(components['ygg_pubkey']))
        base += bytes.fromhex(ygg_hash)
    
    # Add nonce and final hash
    base += bytes.fromhex(components['tpm_nonce'])
    return await compute_hash(base)

# Tests
class TestHashingAlgorithm:
    
    @pytest.mark.asyncio
    @given(components=identity_components_strategy())
    @settings(max_examples=100)
    async def test_identity_hash_deterministic(self, components):
        """Test that identity hash is deterministic"""
        hash1 = await compute_identity_v2(components)
        hash2 = await compute_identity_v2(components)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex length
    
    @pytest.mark.asyncio
    @given(comp1=identity_components_strategy(), comp2=identity_components_strategy())
    async def test_identity_hash_uniqueness(self, comp1, comp2):
        """Test that different components produce different hashes"""
        # Ensure components are different
        assume(comp1 != comp2)
        
        hash1 = await compute_identity_v2(comp1)
        hash2 = await compute_identity_v2(comp2)
        
        assert hash1 != hash2
    
    @pytest.mark.asyncio
    @given(components=identity_components_strategy())
    async def test_nonce_changes_hash(self, components):
        """Test that changing nonce changes the hash"""
        hash1 = await compute_identity_v2(components)
        
        # Change nonce
        components['tpm_nonce'] = hashlib.sha256(b'different').hexdigest()
        hash2 = await compute_identity_v2(components)
        
        assert hash1 != hash2
    
    @pytest.mark.asyncio
    @given(components=identity_components_strategy())
    async def test_device_name_affects_hash(self, components):
        """Test that device name properly affects hash"""
        # Without device name
        components['device_name'] = None
        hash_without = await compute_identity_v2(components)
        
        # With device name
        components['device_name'] = 'laptop'
        hash_with = await compute_identity_v2(components)
        
        assert hash_without != hash_with
    
    @pytest.mark.asyncio
    @given(components=identity_components_strategy())
    async def test_yggdrasil_optional_binding(self, components):
        """Test Yggdrasil binding only affects hash when enabled"""
        # Generate Ygg pubkey
        components['ygg_pubkey'] = hashlib.sha256(b'yggdrasil').hexdigest()
        
        # Test with include_ygg = False
        components['include_ygg'] = False
        hash_without = await compute_identity_v2(components)
        
        # Test with include_ygg = True
        components['include_ygg'] = True
        hash_with = await compute_identity_v2(components)
        
        assert hash_without != hash_with
        
        # Test that ygg_pubkey without include_ygg doesn't affect hash
        components['include_ygg'] = False
        hash_disabled = await compute_identity_v2(components)
        
        components['ygg_pubkey'] = None
        hash_no_ygg = await compute_identity_v2(components)
        
        assert hash_disabled == hash_no_ygg
    
    @pytest.mark.asyncio
    async def test_empty_components_fail(self):
        """Test that empty components raise appropriate errors"""
        empty_components = {
            'tpm_pubkey': '',
            'dilithium_sig': '',
            'emercoin_sig': '',
            'yubikey_cert': '',
            'tpm_nonce': ''
        }
        
        with pytest.raises(ValueError, binascii.Error):
            await compute_identity_v2(empty_components)
    
    @pytest.mark.asyncio
    @given(
        tpm_key=tpm_pubkey_strategy(),
        dilithium=dilithium_signature_strategy(),
        emercoin=emercoin_signature_strategy(),
        yubikey=yubikey_cert_strategy()
    )
    async def test_component_size_bounds(self, tpm_key, dilithium, emercoin, yubikey):
        """Test that component sizes are within expected bounds"""
        # TPM key
        assert 256 <= len(bytes.fromhex(tpm_key)) <= 512
        
        # Dilithium signature (base64 decoded)
        assert len(base64.b64decode(dilithium)) == 3293
        
        # Emercoin signature
        assert 64 <= len(base64.b64decode(emercoin)) <= 72
        
        # YubiKey cert
        assert 500 <= len(bytes.fromhex(yubikey)) <= 2000
    
    @pytest.mark.asyncio
    @given(st.data())
    async def test_identity_format_consistency(self, data):
        """Test identity format remains consistent across operations"""
        components = data.draw(identity_components_strategy())
        
        # Compute identity
        identity = await compute_identity_v2(components)
        
        # Verify format
        assert isinstance(identity, str)
        assert len(identity) == 64
        assert all(c in '0123456789abcdef' for c in identity)
        
        # Test with same components produces same format
        identity2 = await compute_identity_v2(components.copy())
        assert identity == identity2