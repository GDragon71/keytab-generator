import os
import struct
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import io

class KeytabGenerator:
    """Generate Kerberos keytab files"""
    
    # Encryption types
    ENCTYPE_RC4_HMAC = 23
    ENCTYPE_AES256_CTS_HMAC_SHA1_96 = 18
    ENCTYPE_AES128_CTS_HMAC_SHA1_96 = 17
    
    @staticmethod
    def derive_rc4_key(password: str) -> bytes:
        """Derive RC4-HMAC key from password"""
        password_bytes = password.encode('utf-16-le')
        return hashlib.md4(password_bytes).digest()
    
    @staticmethod
    def derive_aes256_key(password: str, salt: str) -> bytes:
        """Derive AES256 key from password using PBKDF2"""
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        
        # Use PBKDF2 with SHA1 (Kerberos standard for AES256)
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        
        kdf = PBKDF2(
            algorithm=hashes.SHA1(),
            length=32,  # 256 bits for AES256
            salt=salt_bytes,
            iterations=4096,  # Kerberos standard
            backend=default_backend()
        )
        return kdf.derive(password_bytes)
    
    @staticmethod
    def derive_aes128_key(password: str, salt: str) -> bytes:
        """Derive AES128 key from password using PBKDF2"""
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        
        kdf = PBKDF2(
            algorithm=hashes.SHA1(),
            length=16,  # 128 bits for AES128
            salt=salt_bytes,
            iterations=4096,
            backend=default_backend()
        )
        return kdf.derive(password_bytes)
    
    @classmethod
    def generate_keytab(cls, domain: str, spn: str, password: str) -> bytes:
        """
        Generate a keytab file from domain, SPN, and password.
        
        Args:
            domain: Kerberos realm (e.g., EXAMPLE.COM)
            spn: Service Principal Name (e.g., HTTP/server.example.com)
            password: Password for the service principal
            
        Returns:
            Binary keytab file content
        """
        keytab = io.BytesIO()
        
        # Keytab file format version
        keytab.write(struct.pack('>H', 0x0502))  # File format version 5.2
        
        # Parse SPN into service and host
        if '/' in spn:
            service, host = spn.split('/', 1)
        else:
            service = spn
            host = f'host.{domain.lower()}'
        
        # Prepare principal components
        realm = domain.upper()
        principal_components = [service, host]
        
        # Timestamp
        timestamp = int(datetime.utcnow().timestamp())
        
        # Generate keys: RC4-HMAC
        rc4_key = cls.derive_rc4_key(password)
        
        # Generate AES256 key (salt is "DOMAIN.COMservice")
        salt = f"{realm}{service}"
        aes256_key = cls.derive_aes256_key(password, salt)
        
        # Generate AES128 key
        aes128_key = cls.derive_aes128_key(password, salt)
        
        # Write principal name
        principal_data = io.BytesIO()
        
        # Helper to write strings
        def write_string(data, s):
            s_bytes = s.encode('utf-8')
            data.write(struct.pack('>H', len(s_bytes)))
            data.write(s_bytes)
        
        # Write realm
        write_string(principal_data, realm)
        
        # Write principal components
        principal_data.write(struct.pack('>I', len(principal_components)))
        for comp in principal_components:
            write_string(principal_data, comp)
        
        # Name type (1 = KRB5_NT_PRINCIPAL)
        principal_data.write(struct.pack('>I', 1))
        
        principal_bytes = principal_data.getvalue()
        
        # Write entries for each encryption type
        for enctype, key in [(cls.ENCTYPE_RC4_HMAC, rc4_key),
                             (cls.ENCTYPE_AES256_CTS_HMAC_SHA1_96, aes256_key),
                             (cls.ENCTYPE_AES128_CTS_HMAC_SHA1_96, aes128_key)]:
            
            entry = io.BytesIO()
            
            # Entry size placeholder
            size_pos = entry.tell()
            entry.write(struct.pack('>I', 0))  # Placeholder
            
            # Principal
            entry.write(principal_bytes)
            
            # Timestamp (seconds)
            entry.write(struct.pack('>I', timestamp))
            
            # Key version number
            entry.write(struct.pack('>B', 0))
            
            # Key type and value
            entry.write(struct.pack('>H', enctype))
            entry.write(struct.pack('>H', len(key)))
            entry.write(key)
            
            # Write entry size at the beginning
            entry_data = entry.getvalue()
            entry_size = len(entry_data) - 4  # Don't include the size field itself
            entry_data = struct.pack('>I', entry_size) + entry_data[4:]
            
            keytab.write(entry_data)
        
        return keytab.getvalue()
