# Kerberos Keytab Generator

A standalone Python tool for generating and inspecting Kerberos keytab files without access to a KDC (Key Distribution Center).

## Features

- ✓ Generate keytab files from SPN, domain, and password
- ✓ Read and inspect keytab file contents
- ✓ Validate keytab binary format
- ✓ Works offline (no network/KDC required)
- ✓ Cross-platform support (Linux, macOS, Windows)
- ✓ AES256-CTS-HMAC-SHA1-96 encryption (modern standard)
- ✓ Secure password input (hidden from screen)
- ✓ **Harness Integration**: Retrieve AD credentials from HashiCorp Vault
- ✓ **AppRole Authentication**: Secure authentication to Vault via AppRole
- ✓ **Temporary File Management**: Auto-generated filenames with secure cleanup

## Installation

### Requirements

- Python 3.6+
- cryptography library

### Setup

1. Clone or download this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Harness Integration Guide

For CI/CD automation with Harness pipelines, use the dedicated Harness CLI tool that retrieves credentials from HashiCorp Vault.

#### Prerequisites
- HashiCorp Vault instance configured with AppRole auth method
- AD service account credentials stored in Vault KV v2 engine
- AppRole credentials (Role ID and Secret ID)

#### Step 1: Generate Keytab from Vault

Use the `harness_keytab.py` script in your Harness pipeline:

```bash
python3 app/harness_keytab.py \
  --vault-addr https://vault.example.com:8200 \
  --role-id <ROLE_ID> \
  --secret-id <SECRET_ID> \
  --secret-path ad-accounts/service1 \
  --domain EXAMPLE.COM \
  --spn HTTP/server.example.com \
  --output /tmp/http.keytab
```

**Arguments:**
- `--vault-addr` - Vault server address
- `--role-id` - AppRole Role ID
- `--secret-id` - AppRole Secret ID
- `--secret-path` - Path to secret in KV v2 (e.g., `ad-accounts/service1`)
- `--domain` - Kerberos realm (e.g., `EXAMPLE.COM`)
- `--spn` - Service Principal Name (e.g., `HTTP/server.example.com`)
- `--output` - Output file path (optional, auto-generated if omitted)
- `--username-field` - Field name for username in secret (default: `username`)
- `--password-field` - Field name for password in secret (default: `password`)
- `--no-verify-ssl` - Disable SSL verification (not recommended)
- `--json` - Output result as JSON

**Returns:**
```
[SUCCESS] Keytab file generated: /tmp/http.keytab
[INFO] File size: 94 bytes
[INFO] Permissions: 600 (owner read/write only)

Keytab file ready for rsync: /tmp/http.keytab
```

#### Step 2: Copy Keytab via rsync

Copy the generated keytab from Kubernetes node to target Linux VM:

```bash
KEYTAB_PATH=$(python3 app/harness_keytab.py \
  --vault-addr https://vault.example.com:8200 \
  --role-id $VAULT_ROLE_ID \
  --secret-id $VAULT_SECRET_ID \
  --secret-path ad-accounts/service1 \
  --domain EXAMPLE.COM \
  --spn HTTP/server.example.com | grep "Keytab file ready" | awk '{print $NF}')

rsync -avz "$KEYTAB_PATH" target-vm:/etc/krb5.keytab
```

Or with explicit output path:

```bash
KEYTAB_PATH="/tmp/http_$(date +%s).keytab"

python3 app/harness_keytab.py \
  --vault-addr https://vault.example.com:8200 \
  --role-id $VAULT_ROLE_ID \
  --secret-id $VAULT_SECRET_ID \
  --secret-path ad-accounts/service1 \
  --domain EXAMPLE.COM \
  --spn HTTP/server.example.com \
  --output "$KEYTAB_PATH"

rsync -avz "$KEYTAB_PATH" target-vm:/etc/krb5.keytab
```

#### Step 3: Clean Up Temporary File

After rsync completes, securely delete the temporary keytab:

```bash
python3 app/cleanup_keytab.py --file "$KEYTAB_PATH" --secure --verbose
```

**Arguments for cleanup:**
- `--file` - Path to keytab file to delete
- `--secure` - Use secure deletion with random overwrite (default: simple deletion)
- `--passes` - Number of overwrite passes (default: 3)
- `--verbose` - Print verbose output
- `--json` - Output result as JSON

#### Complete Harness Stage Example

```yaml
stage:
  name: Deploy with Keytab
  spec:
    steps:
      - step:
          type: ShellScript
          name: Generate and Deploy Keytab
          spec:
            shell: Bash
            command: |
              set -e
              
              # Generate keytab from Vault
              KEYTAB_PATH=$(mktemp --suffix=.keytab)
              
              python3 app/harness_keytab.py \
                --vault-addr ${VAULT_ADDR} \
                --role-id ${VAULT_ROLE_ID} \
                --secret-id ${VAULT_SECRET_ID} \
                --secret-path ${VAULT_SECRET_PATH} \
                --domain ${AD_DOMAIN} \
                --spn ${AD_SPN} \
                --output "$KEYTAB_PATH" \
                --json > /tmp/keytab_result.json
              
              # Extract path from JSON output (optional)
              KEYTAB_PATH=$(cat /tmp/keytab_result.json | grep -o '"keytab_path":"[^"]*' | cut -d'"' -f4)
              
              # Copy to target VM
              rsync -avz -e "ssh -i ${K8S_NODE_SSH_KEY}" \
                "$KEYTAB_PATH" \
                ${DEPLOY_USER}@${TARGET_VM}:/etc/krb5.keytab
              
              # Clean up local file
              python3 app/cleanup_keytab.py --file "$KEYTAB_PATH" --secure --verbose
              
              echo "Keytab deployed successfully"
            envVariables:
              VAULT_ADDR: <+secrets.getValue("vault_addr")>
              VAULT_ROLE_ID: <+secrets.getValue("vault_role_id")>
              VAULT_SECRET_ID: <+secrets.getValue("vault_secret_id")>
              VAULT_SECRET_PATH: <+secrets.getValue("ad_credential_path")>
              AD_DOMAIN: <+secrets.getValue("ad_domain")>
              AD_SPN: <+secrets.getValue("ad_spn")>
              TARGET_VM: <+secrets.getValue("target_vm_ip")>
              DEPLOY_USER: <+secrets.getValue("deploy_user")>
              K8S_NODE_SSH_KEY: /etc/secrets/k8s_node_ssh_key
```

### Generate a Keytab File

Generate a keytab by providing domain and SPN. Password will be prompted (hidden):

```bash
python3 keytab.py --domain EXAMPLE.COM --spn HTTP/server.example.com
```

Optional: Specify output file path (defaults to auto-named file in current directory):

```bash
python3 keytab.py --domain EXAMPLE.COM --spn HTTP/server.example.com --output mykey.keytab
```

**Arguments:**
- `--domain REALM` - Kerberos realm/domain (e.g., `EXAMPLE.COM`)
- `--spn PRINCIPAL` - Service Principal Name (e.g., `HTTP/server.example.com`)
- `--output FILE` - Optional output file path (auto-named if omitted)

**Output:**
- Success message with file details
- Auto-generated filename format: `SERVICE_HOSTNAME.keytab` or `SERVICE.keytab`
- Automatic validation of generated keytab

### Read/Inspect a Keytab File

Parse and display keytab contents:

```bash
python3 keytab.py --read mykey.keytab
```

Shows:
- Keytab version
- Principal name (realm + components)
- Encryption algorithm
- Key version number
- Timestamp
- Key length

## Examples

### Example 1: Generate a keytab for an HTTP service

```bash
$ python3 keytab.py --domain EXAMPLE.COM --spn HTTP/web.example.com
Enter password for service account: 
Generating keytab...
✓ Keytab file generated successfully: HTTP_web.keytab
  File size: 94 bytes
  Realm: EXAMPLE.COM
  Principal: HTTP/web.example.com
  Encryption: AES256-CTS-HMAC-SHA1-96

Verifying keytab format...
Keytab Version: 0x0502
----
Entry 1:
  Principal: HTTP/web.example.com@EXAMPLE.COM
  Encryption Type: AES256-CTS-HMAC-SHA1-96
  Key Version: 0
  Timestamp: 2026-02-22 12:34:56 UTC
  Key Length: 32 bytes

✓ Keytab validation passed
```

### Example 2: Generate with custom output path

```bash
$ python3 keytab.py --domain CORP.LOCAL --spn LDAP/dc.corp.local --output /etc/krb5.keytab
Enter password for service account: 
Generating keytab...
✓ Keytab file generated successfully: /etc/krb5.keytab
  ...
```

### Example 3: Inspect a keytab file

```bash
$ python3 keytab.py --read /etc/krb5.keytab
Keytab Version: 0x0502
----
Entry 1:
  Principal: LDAP/dc.corp.local@CORP.LOCAL
  Encryption Type: AES256-CTS-HMAC-SHA1-96
  Key Version: 0
  Timestamp: 2026-02-22 10:15:00 UTC
  Key Length: 32 bytes
```

## Testing Without a KDC

This tool is designed for offline testing:

1. **Generate a keytab** with your test domain, SPN, and password
2. **Inspect the keytab** with `--read` to verify structure and contents
3. **Use the keytab** for testing without any network connection required

No KDC, network access, or Kerberos infrastructure needed for keytab generation or inspection.

## Security Notes

- **Password Handling**: Passwords are only used to derive cryptographic keys locally. They are never stored in the keytab file or transmitted.
- **Keytab Files**: Generated keytab files contain sensitive cryptographic material. Protect them as you would passwords.
- **Permissions**: On Unix-like systems, restrict file permissions: `chmod 600 keytab.keytab`
- **Storage**: Keep keytab files in secure locations with restricted access.
- **Vault Integration**: 
  - AppRole credentials (Role ID and Secret ID) are used to authenticate to Vault
  - Always store Vault credentials in Harness secrets management
  - Never commit AppRole credentials to version control
  - Use short-lived Secret IDs when possible
- **Temporary Files**: 
  - Generated keytab files should be treated as temporary and destroyed after use
  - Use `cleanup_keytab.py` with `--secure` flag for sensitive environments
  - Configure Harness cleanup steps to ensure files are deleted even if deployment fails
- **SSL/TLS**: 
  - By default, SSL certificate verification is enabled for Vault connections
  - Only disable with `--no-verify-ssl` in trusted development environments
  - In production, always verify certificates

## Technical Details

### Keytab Format

Generated keytabs follow RFC 3961 Kerberos Format Specification:
- File format version: 5.2 (0x0502)
- Encryption: AES256-CTS-HMAC-SHA1-96
- Key derivation: PBKDF2-HMAC-SHA1 with 4096 iterations
- Salt format: `{REALM}{SERVICE}`

### Exit Codes

- `0` - Success
- `1` - Error (validation failed, file issues, etc.)

## Troubleshooting

### "cryptography library not found"
Install dependencies:
```bash
pip install cryptography
```

### File permission denied
Ensure you have write permissions to the output directory.

### Import errors on different Python versions
Use Python 3.6 or newer and ensure cryptography is properly installed for your Python version.

## License

MIT

## Vault AppRole Setup Guide

To use the Harness integration, you'll need to configure AppRole authentication in HashiCorp Vault.

### 1. Enable AppRole Auth Method

```bash
vault auth enable approle
```

### 2. Create AppRole for Harness

```bash
vault write auth/approle/role/harness-keytab \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=1h \
  bind_secret_id=true
```

### 3. Create Policy

```bash
vault policy write harness-keytab -<<EOF
path "secret/data/ad-accounts/*" {
  capabilities = ["read", "list"]
}
EOF
```

### 4. Attach Policy to AppRole

```bash
vault write auth/approle/role/harness-keytab \
  token_policies="harness-keytab"
```

### 5. Get Role ID

```bash
vault read auth/approle/role/harness-keytab/role-id
```

### 6. Generate Secret ID

```bash
vault write -f auth/approle/role/harness-keytab/secret-id
```

### 7. Store AD Credentials in Vault

```bash
vault kv put secret/ad-accounts/service1 \
  username="svc_account@EXAMPLE.COM" \
  password="ServiceAccountPassword123!"
```

### 8. Test the Integration

```bash
python3 app/harness_keytab.py \
  --vault-addr https://vault.example.com:8200 \
  --role-id <ROLE_ID> \
  --secret-id <SECRET_ID> \
  --secret-path ad-accounts/service1 \
  --domain EXAMPLE.COM \
  --spn HTTP/test.example.com
```

## Notes

- This tool generates keytab files for testing and legitimate administrative purposes only.
- Keytabs generated by this tool are compatible with Kerberos clients and services.
- For production use, consider using official Kerberos tools (ktutil, kadmin) when access to a KDC is available.

