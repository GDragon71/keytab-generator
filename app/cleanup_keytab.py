#!/usr/bin/env python3
"""
Secure Keytab Cleanup Utility
Safely removes temporary keytab files with secure deletion.
"""

import argparse
import sys
import os
import shutil
import hashlib
from pathlib import Path


class SecureKeytabCleanup:
    """Secure deletion of keytab files"""
    
    @staticmethod
    def securely_delete(file_path: str, overwrite_passes: int = 3, verbose: bool = False) -> bool:
        """
        Securely delete a keytab file by overwriting with random data before deletion.
        
        Args:
            file_path: Path to file to delete
            overwrite_passes: Number of overwrite passes (default: 3)
            verbose: Print verbose output
            
        Returns:
            True if successfully deleted, False otherwise
        """
        if not os.path.exists(file_path):
            if verbose:
                print(f"[WARNING] File does not exist: {file_path}")
            return False
        
        if not os.path.isfile(file_path):
            if verbose:
                print(f"[ERROR] Path is not a file: {file_path}")
            return False
        
        file_size = os.path.getsize(file_path)
        
        if verbose:
            print(f"[INFO] Securely deleting file: {file_path}")
            print(f"[INFO] File size: {file_size} bytes")
        
        try:
            # Overwrite file content
            for pass_num in range(overwrite_passes):
                # Create random data for overwriting
                random_data = os.urandom(file_size)
                
                # Write random data to file
                with open(file_path, 'wb') as f:
                    f.write(random_data)
                
                if verbose:
                    print(f"[INFO] Overwrite pass {pass_num + 1}/{overwrite_passes}")
            
            # Delete the file
            os.remove(file_path)
            
            if verbose:
                print(f"[SUCCESS] File securely deleted: {file_path}")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to securely delete file: {e}", file=sys.stderr)
            return False
    
    @staticmethod
    def simple_delete(file_path: str, verbose: bool = False) -> bool:
        """
        Simple file deletion (standard os.remove).
        
        Args:
            file_path: Path to file to delete
            verbose: Print verbose output
            
        Returns:
            True if successfully deleted, False otherwise
        """
        if not os.path.exists(file_path):
            if verbose:
                print(f"[WARNING] File does not exist: {file_path}")
            return False
        
        try:
            os.remove(file_path)
            
            if verbose:
                print(f"[SUCCESS] File deleted: {file_path}")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to delete file: {e}", file=sys.stderr)
            return False


def main():
    parser = argparse.ArgumentParser(
        prog='cleanup-keytab',
        description='Securely delete temporary keytab files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Simple deletion
  python3 cleanup_keytab.py --file /tmp/http_server.keytab

  # Secure deletion with multiple overwrite passes
  python3 cleanup_keytab.py --file /tmp/http_server.keytab --secure --passes 5

  # Verbose output
  python3 cleanup_keytab.py --file /tmp/http_server.keytab --verbose
        """
    )
    
    parser.add_argument('--file', required=True, help='Path to keytab file to delete')
    parser.add_argument('--secure', action='store_true', help='Use secure deletion with random overwrite')
    parser.add_argument('--passes', type=int, default=3, help='Number of overwrite passes for secure deletion (default: 3)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--json', action='store_true', help='Output result as JSON')
    
    args = parser.parse_args()
    
    import json
    
    try:
        # Resolve the file path
        file_path = os.path.abspath(args.file)
        
        # Determine deletion method
        if args.secure:
            success = SecureKeytabCleanup.securely_delete(
                file_path,
                overwrite_passes=args.passes,
                verbose=args.verbose
            )
        else:
            success = SecureKeytabCleanup.simple_delete(
                file_path,
                verbose=args.verbose
            )
        
        if args.json:
            result = {
                'status': 'success' if success else 'failed',
                'file': file_path,
                'deleted': success
            }
            print(json.dumps(result, indent=2))
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("[ERROR] Operation cancelled by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        if args.json:
            error_result = {
                'status': 'error',
                'file': args.file,
                'error': str(e)
            }
            print(json.dumps(error_result, indent=2))
        sys.exit(1)


if __name__ == '__main__':
    main()
