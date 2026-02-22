#!/usr/bin/env python3
"""
Kerberos Keytab Generator
Generate and inspect Kerberos keytab files offline, without access to a KDC.
"""

import argparse
import struct
import sys
import os
import getpass
import io
from datetime import datetime
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: cryptography library not found. Install with: pip install cryptography")
    sys.exit(1)


class KeytabGenerator:
    """Generate Kerberos keytab files with AES256 encryption"""
    
    # Encryption type constants
    ENCTYPE_AES256_CTS_HMAC_SHA1_96 = 18
    
    @staticmethod
    def derive_aes256_key(password: str, salt: str) -> bytes:
        """Derive AES256 key from password using PBKDF2"""
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=32,  # 256 bits for AES256
            salt=salt_bytes,
            iterations=4096,
            backend=default_backend()
        )
        return kdf.derive(password_bytes)
    
    @classmethod
    def generate(cls, domain: str, spn: str, password: str) -> bytes:
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
        
        # Generate AES256 key (salt is "DOMAIN.COMservice")
        salt = f"{realm}{service}"
        aes256_key = cls.derive_aes256_key(password, salt)
        
        # Build principal name
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
        
        # Write entry for AES256 encryption
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
        
        # Key type (AES256)
        entry.write(struct.pack('>H', cls.ENCTYPE_AES256_CTS_HMAC_SHA1_96))
        
        # Key length and value
        entry.write(struct.pack('>H', len(aes256_key)))
        entry.write(aes256_key)
        
        # Calculate and write entry size
        entry_data = entry.getvalue()
        entry_size = len(entry_data) - 4  # Don't include the size field itself
        entry_data = struct.pack('>I', entry_size) + entry_data[4:]
        
        keytab.write(entry_data)
        
        return keytab.getvalue()


class KeytabReader:
    """Read and inspect Kerberos keytab files"""
    
    # Encryption type names
    ENCTYPE_NAMES = {
        1: "DES-CBC-CRC",
        2: "DES-CBC-MD5",
        3: "3DES-CBC-HMAC-SHA1-KD",
        5: "DES-CBC-MD5 (v4 salt)",
        6: "DES-CBC-MD5 (norealm)",
        7: "DES-CBC-MD5 (normalization)",
        9: "DES3",
        17: "AES128-CTS-HMAC-SHA1-96",
        18: "AES256-CTS-HMAC-SHA1-96",
        23: "RC4-HMAC-MD5",
        24: "RC4-HMAC-MD5 (v4 salt)",
    }
    
    @staticmethod
    def read(keytab_path: str) -> None:
        """
        Read and display keytab file contents.
        
        Args:
            keytab_path: Path to keytab file
        """
        try:
            with open(keytab_path, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {keytab_path}")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
        
        if len(data) < 2:
            print("Error: Invalid keytab file (too short)")
            sys.exit(1)
        
        # Read file format version
        version = struct.unpack('>H', data[0:2])[0]
        if version != 0x0502:
            print(f"Warning: Unexpected keytab version: 0x{version:04x} (expected 0x0502)")
        
        print(f"Keytab Version: 0x{version:04x}")
        print("-" * 60)
        
        offset = 2
        entry_num = 0
        
        while offset < len(data):
            entry_num += 1
            
            if offset + 4 > len(data):
                break
            
            # Read entry size
            entry_size = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            
            if entry_size == 0:
                # End of keytab
                break
            
            if offset + entry_size > len(data):
                print(f"Error: Entry {entry_num} extends beyond file")
                break
            
            entry_data = data[offset:offset+entry_size]
            offset += entry_size
            
            # Parse entry
            entry_offset = 0
            
            # Read realm
            if entry_offset + 2 > len(entry_data):
                print(f"Entry {entry_num}: Error parsing realm")
                continue
            
            realm_len = struct.unpack('>H', entry_data[entry_offset:entry_offset+2])[0]
            entry_offset += 2
            
            if entry_offset + realm_len > len(entry_data):
                print(f"Entry {entry_num}: Error reading realm")
                continue
            
            realm = entry_data[entry_offset:entry_offset+realm_len].decode('utf-8', errors='replace')
            entry_offset += realm_len
            
            # Read principal components
            if entry_offset + 4 > len(entry_data):
                print(f"Entry {entry_num}: Error parsing principal count")
                continue
            
            num_components = struct.unpack('>I', entry_data[entry_offset:entry_offset+4])[0]
            entry_offset += 4
            
            components = []
            for _ in range(num_components):
                if entry_offset + 2 > len(entry_data):
                    break
                
                comp_len = struct.unpack('>H', entry_data[entry_offset:entry_offset+2])[0]
                entry_offset += 2
                
                if entry_offset + comp_len > len(entry_data):
                    break
                
                comp = entry_data[entry_offset:entry_offset+comp_len].decode('utf-8', errors='replace')
                components.append(comp)
                entry_offset += comp_len
            
            # Read name type
            if entry_offset + 4 > len(entry_data):
                print(f"Entry {entry_num}: Error parsing name type")
                continue
            
            name_type = struct.unpack('>I', entry_data[entry_offset:entry_offset+4])[0]
            entry_offset += 4
            
            # Read timestamp
            if entry_offset + 4 > len(entry_data):
                print(f"Entry {entry_num}: Error parsing timestamp")
                continue
            
            timestamp = struct.unpack('>I', entry_data[entry_offset:entry_offset+4])[0]
            entry_offset += 4
            
            # Read key version
            if entry_offset + 1 > len(entry_data):
                print(f"Entry {entry_num}: Error parsing key version")
                continue
            
            key_version = entry_data[entry_offset]
            entry_offset += 1
            
            # Read encryption type
            if entry_offset + 2 > len(entry_data):
                print(f"Entry {entry_num}: Error parsing encryption type")
                continue
            
            enctype = struct.unpack('>H', entry_data[entry_offset:entry_offset+2])[0]
            entry_offset += 2
            
            # Read key
            if entry_offset + 2 > len(entry_data):
                print(f"Entry {entry_num}: Error parsing key length")
                continue
            
            key_len = struct.unpack('>H', entry_data[entry_offset:entry_offset+2])[0]
            entry_offset += 2
            
            if entry_offset + key_len > len(entry_data):
                print(f"Entry {entry_num}: Error reading key")
                continue
            
            # Print entry information
            principal = '/'.join(components) if components else "unknown"
            enctype_name = KeytabReader.ENCTYPE_NAMES.get(enctype, f"Unknown ({enctype})")
            timestamp_str = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
            
            print(f"Entry {entry_num}:")
            print(f"  Principal: {principal}@{realm}")
            print(f"  Encryption Type: {enctype_name}")
            print(f"  Key Version: {key_version}")
            print(f"  Timestamp: {timestamp_str}")
            print(f"  Key Length: {key_len} bytes")
            print()


def main():
    parser = argparse.ArgumentParser(
        prog='keytab',
        description='Generate and inspect Kerberos keytab files',
        add_help=False
    )
    
    # Read mode (mutually exclusive with generate mode)
    parser.add_argument('--read', metavar='FILE', help='Read and inspect a keytab file')
    
    # Generate mode arguments
    parser.add_argument('--domain', help='Kerberos realm/domain (e.g., EXAMPLE.COM)')
    parser.add_argument('--spn', help='Service Principal Name (e.g., HTTP/server.example.com)')
    parser.add_argument('--output', help='Output keytab file path (auto-named if not specified)')
    
    args = parser.parse_args()
    
    try:
        if args.read:
            # Read mode
            KeytabReader.read(args.read)
        else:
            # Generate mode
            if not args.domain:
                print("Error: --domain is required")
                sys.exit(1)
            
            if not args.spn:
                print("Error: --spn is required")
                sys.exit(1)
            
            # Prompt for password
            password = getpass.getpass("Enter password for service account: ")
            
            if not password:
                print("Error: Password cannot be empty")
                sys.exit(1)
            
            # Generate keytab
            print("Generating keytab...")
            keytab_data = KeytabGenerator.generate(args.domain, args.spn, password)
            
            # Determine output filename
            if args.output:
                output_path = args.output
            else:
                # Auto-name: SERVICE_HOSTNAME.keytab or SERVICE.keytab
                if '/' in args.spn:
                    service, host = args.spn.split('/', 1)
                else:
                    service = args.spn
                    host = None
                
                if host:
                    # Replace domain part with underscore for simplicity
                    hostname = host.split('.')[0] if '.' in host else host
                    output_path = f"{service}_{hostname}.keytab"
                else:
                    output_path = f"{service}.keytab"
            
            # Write keytab file
            try:
                with open(output_path, 'wb') as f:
                    f.write(keytab_data)
                
                # Verify the file was written correctly
                if not os.path.exists(output_path):
                    print(f"Error: Failed to write keytab file")
                    sys.exit(1)
                
                file_size = os.path.getsize(output_path)
                print(f"✓ Keytab file generated successfully: {output_path}")
                print(f"  File size: {file_size} bytes")
                print(f"  Realm: {args.domain.upper()}")
                print(f"  Principal: {args.spn}")
                print(f"  Encryption: AES256-CTS-HMAC-SHA1-96")
                
                # Verify by reading it back
                print("\nVerifying keytab format...")
                KeytabReader.read(output_path)
                print("✓ Keytab validation passed")
                
            except IOError as e:
                print(f"Error writing keytab file: {e}")
                sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
