#!/usr/bin/env python3
"""
Harness Kerberos Keytab Generator
Generates keytab files from AD credentials stored in HashiCorp Vault.
Designed for use in Harness pipelines.
"""

import argparse
import sys
import os
import json
import hvac
from pathlib import Path
from keytab_generator import KeytabGenerator


class VaultClient:
    """Secure client for HashiCorp Vault"""
    
    def __init__(self, vault_addr: str, role_id: str, secret_id: str, verify_ssl: bool = True):
        """
        Initialize Vault client with AppRole authentication.
        
        Args:
            vault_addr: Vault server address (e.g., https://vault.example.com:8200)
            role_id: AppRole Role ID
            secret_id: AppRole Secret ID
            verify_ssl: Whether to verify SSL certificates (default: True)
        """
        self.vault_addr = vault_addr
        self.verify_ssl = verify_ssl
        self.client = hvac.Client(url=vault_addr, verify=verify_ssl)
        
        try:
            # Authenticate using AppRole
            self.client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id
            )
            if not self.client.is_authenticated():
                raise Exception("Failed to authenticate with Vault")
        except Exception as e:
            raise Exception(f"Vault authentication failed: {e}")
    
    def get_secret(self, secret_path: str) -> dict:
        """
        Retrieve secret from KV v2 engine.
        
        Args:
            secret_path: Path to secret (e.g., 'ad-accounts/service1')
            
        Returns:
            Dictionary containing secret data
        """
        try:
            response = self.client.secrets.kv.v2.read_secret_version(path=secret_path)
            return response['data']['data']
        except hvac.exceptions.InvalidPath:
            raise Exception(f"Secret not found at path: {secret_path}")
        except Exception as e:
            raise Exception(f"Failed to retrieve secret: {e}")
    
    def close(self):
        """Close the Vault client connection"""
        try:
            self.client.logout()
        except:
            pass


class HarnessKeytabGenerator:
    """Generate keytab files from Vault secrets"""
    
    @staticmethod
    def generate_from_vault(
        vault_addr: str,
        role_id: str,
        secret_id: str,
        secret_path: str,
        domain: str,
        spn: str,
        output_path: str = None,
        username_field: str = "username",
        password_field: str = "password",
        verify_ssl: bool = True
    ) -> str:
        """
        Generate keytab file from credentials stored in Vault.
        
        Args:
            vault_addr: Vault server address
            role_id: AppRole Role ID
            secret_id: AppRole Secret ID
            secret_path: Path to secret in KV v2
            domain: Kerberos domain (e.g., EXAMPLE.COM)
            spn: Service Principal Name (e.g., HTTP/server.example.com)
            output_path: Output file path (auto-generated if not specified)
            username_field: Field name for username in secret (default: "username")
            password_field: Field name for password in secret (default: "password")
            verify_ssl: Whether to verify SSL certificates
            
        Returns:
            Path to generated keytab file
        """
        vault_client = None
        
        try:
            # Connect to Vault
            vault_client = VaultClient(vault_addr, role_id, secret_id, verify_ssl)
            
            # Retrieve credentials
            print(f"[INFO] Retrieving credentials from Vault: {secret_path}")
            secret = vault_client.get_secret(secret_path)
            
            # Extract username and password
            if username_field not in secret:
                raise ValueError(f"Field '{username_field}' not found in secret. Available: {list(secret.keys())}")
            if password_field not in secret:
                raise ValueError(f"Field '{password_field}' not found in secret. Available: {list(secret.keys())}")
            
            username = secret[username_field]
            password = secret[password_field]
            
            # Print redacted info
            print(f"[INFO] Retrieved credentials for: {username[:3]}...@{domain}")
            
            # Generate keytab
            print(f"[INFO] Generating keytab file...")
            keytab_data = KeytabGenerator.generate_keytab(domain, spn, password)
            
            # Determine output path
            if not output_path:
                # Auto-generate filename
                if '/' in spn:
                    service, host = spn.split('/', 1)
                    hostname = host.split('.')[0] if '.' in host else host
                    output_path = f"{service}_{hostname}.keytab"
                else:
                    output_path = f"{spn}.keytab"
            
            # Ensure output directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, mode=0o700)
            
            # Write keytab file with restricted permissions
            with open(output_path, 'wb') as f:
                f.write(keytab_data)
            
            # Set restrictive permissions (readable only by owner)
            os.chmod(output_path, 0o600)
            
            # Verify file was created
            if not os.path.exists(output_path):
                raise RuntimeError("Failed to create keytab file")
            
            file_size = os.path.getsize(output_path)
            print(f"[SUCCESS] Keytab file generated: {output_path}")
            print(f"[INFO] File size: {file_size} bytes")
            print(f"[INFO] Permissions: 600 (owner read/write only)")
            
            return output_path
            
        finally:
            # Always close Vault connection
            if vault_client:
                vault_client.close()


def main():
    parser = argparse.ArgumentParser(
        prog='harness-keytab',
        description='Generate Kerberos keytab files from AD credentials in HashiCorp Vault',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate keytab from Vault
  python3 harness_keytab.py \\
    --vault-addr https://vault.example.com:8200 \\
    --role-id abc123 \\
    --secret-id xyz789 \\
    --secret-path ad-accounts/service1 \\
    --domain EXAMPLE.COM \\
    --spn HTTP/server.example.com

  # Generate with custom output path
  python3 harness_keytab.py \\
    --vault-addr https://vault.example.com:8200 \\
    --role-id abc123 \\
    --secret-id xyz789 \\
    --secret-path ad-accounts/service1 \\
    --domain EXAMPLE.COM \\
    --spn HTTP/server.example.com \\
    --output /tmp/my.keytab
        """
    )
    
    # Vault configuration
    parser.add_argument('--vault-addr', required=True, help='Vault server address (e.g., https://vault.example.com:8200)')
    parser.add_argument('--role-id', required=True, help='AppRole Role ID')
    parser.add_argument('--secret-id', required=True, help='AppRole Secret ID')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL certificate verification (not recommended)')
    
    # Secret configuration
    parser.add_argument('--secret-path', required=True, help='Path to secret in KV v2 (e.g., ad-accounts/service1)')
    parser.add_argument('--username-field', default='username', help='Field name for username in secret (default: username)')
    parser.add_argument('--password-field', default='password', help='Field name for password in secret (default: password)')
    
    # Kerberos configuration
    parser.add_argument('--domain', required=True, help='Kerberos realm/domain (e.g., EXAMPLE.COM)')
    parser.add_argument('--spn', required=True, help='Service Principal Name (e.g., HTTP/server.example.com)')
    
    # Output
    parser.add_argument('--output', help='Output keytab file path (auto-generated if not specified)')
    parser.add_argument('--json', action='store_true', help='Output result as JSON')
    
    args = parser.parse_args()
    
    try:
        # Generate keytab from Vault
        keytab_path = HarnessKeytabGenerator.generate_from_vault(
            vault_addr=args.vault_addr,
            role_id=args.role_id,
            secret_id=args.secret_id,
            secret_path=args.secret_path,
            domain=args.domain,
            spn=args.spn,
            output_path=args.output,
            username_field=args.username_field,
            password_field=args.password_field,
            verify_ssl=not args.no_verify_ssl
        )
        
        # Output result
        if args.json:
            result = {
                'status': 'success',
                'keytab_path': keytab_path,
                'domain': args.domain,
                'spn': args.spn
            }
            print(json.dumps(result, indent=2))
        else:
            print(f"\nKeytab file ready for rsync: {keytab_path}")
        
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n[ERROR] Operation cancelled by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        if args.json:
            error_result = {
                'status': 'error',
                'error': str(e)
            }
            print(json.dumps(error_result, indent=2))
        sys.exit(1)


if __name__ == '__main__':
    main()
