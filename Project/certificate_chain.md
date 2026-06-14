# Certificate Authority Implementation and Deployment Guide for Linux

## Overview

This guide demonstrates the practical implementation of a Certificate Authority
(CA) infrastructure on Linux. It covers the creation of a Root CA, an
Intermediate CA, the issuance of server and client certificates, the
management of certificate revocation, the deployment of Mutual TLS (mTLS),
and the automated renewal of certificates before expiry.

---

## Lab Environment Setup

Before starting, update your system and install the required tools:

```bash
sudo apt update
sudo apt install openssl apache2 nginx tree vim curl
```

### Directory Structure

A clean and consistent directory structure is essential for managing a CA
safely. The following layout separates the Root CA and Intermediate CA into
distinct directories:

```bash
sudo mkdir -p /opt/ca/{root-ca,intermediate-ca}
cd /opt/ca

# Root CA subdirectories
sudo mkdir -p root-ca/{certs,crl,newcerts,private,csr}

# Intermediate CA subdirectories
sudo mkdir -p intermediate-ca/{certs,crl,newcerts,private,csr}

# Restrict access to private key directories
sudo chmod 700 root-ca/private intermediate-ca/private
sudo chmod 755 root-ca intermediate-ca

# Initialize the certificate database and serial files
sudo touch root-ca/index.txt
sudo echo 1000 | sudo tee root-ca/serial
sudo touch intermediate-ca/index.txt
sudo echo 1000 | sudo tee intermediate-ca/serial
sudo echo 1000 | sudo tee intermediate-ca/crlnumber
```

---

## Part 1 — Root Certificate Authority

### Step 1: Configure the Root CA

The `openssl.cnf` file controls all CA behavior. The Root CA uses a strict
naming policy, meaning that any certificate it signs must have the same
country, state, and organization as the Root CA itself.

Create the configuration file at `/opt/ca/root-ca/openssl.cnf`:

```ini
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /opt/ca/root-ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
default_days      = 3650
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                    = Country Name (2 letter code)
stateOrProvinceName            = State or Province Name
localityName                   = Locality Name
0.organizationName             = Organization Name
organizationalUnitName         = Organizational Unit Name
commonName                     = Common Name
emailAddress                   = Email Address
countryName_default            = BE
stateOrProvinceName_default    = Brussels
localityName_default           = Brussels
0.organizationName_default     = ULB Cybersecurity Lab
organizationalUnitName_default = IT Department
emailAddress_default           = admin@cybersec.ulb.ac.be

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ crl_ext ]
authorityKeyIdentifier = keyid:always
```

### Step 2: Generate the Root CA Private Key

The Root CA key is a 4096-bit RSA key encrypted with AES-256. Strict
permissions are applied immediately after generation to prevent unauthorized
access.

```bash
cd /opt/ca/root-ca

sudo openssl genrsa -aes256 -out private/ca.key.pem 4096
sudo chmod 400 private/ca.key.pem
```

### Step 3: Create the Root CA Certificate

The Root CA certificate is self-signed and is given a validity period of
20 years (7300 days), since the entire hierarchy depends on it remaining valid.

```bash
sudo openssl req -config openssl.cnf \
  -key private/ca.key.pem \
  -new -x509 -days 7300 -sha256 \
  -extensions v3_ca \
  -out certs/ca.cert.pem

sudo openssl x509 -noout -text -in certs/ca.cert.pem
sudo chmod 444 certs/ca.cert.pem
```

When prompted, enter the following values:

| Field | Example Value |
|---|---|
| Country Name | BE |
| State | Brussels |
| Locality | Brussels |
| Organization | ULB Cybersecurity Lab |
| Organizational Unit | Root CA |
| Common Name | ULB Cybersecurity Root CA |
| Email | rootca@cybersec.ulb.ac.be |

---

## Part 2 — Intermediate Certificate Authority

### Step 4: Configure the Intermediate CA

The Intermediate CA uses a looser naming policy (`policy_loose`), allowing
it to issue certificates to entities whose DN fields do not need to match
its own. Its default certificate validity is 375 days, in line with current
browser requirements.

Create the configuration file at `/opt/ca/intermediate-ca/openssl.cnf`:

```ini
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /opt/ca/intermediate-ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand
private_key       = $dir/private/intermediate.key.pem
certificate       = $dir/certs/intermediate.cert.pem
crlnumber         = $dir/crlnumber
crl               = $dir/crl/intermediate.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256

[ req_distinguished_name ]
countryName                    = Country Name (2 letter code)
stateOrProvinceName            = State or Province Name
localityName                   = Locality Name
0.organizationName             = Organization Name
organizationalUnitName         = Organizational Unit Name
commonName                     = Common Name
emailAddress                   = Email Address
countryName_default            = BE
stateOrProvinceName_default    = Brussels
localityName_default           = Brussels
0.organizationName_default     = ULB Cybersecurity Lab
organizationalUnitName_default = IT Department
emailAddress_default           = admin@cybersec.ulb.ac.be

[ server_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth

[ client_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage               = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth, emailProtection

[ crl_ext ]
authorityKeyIdentifier = keyid:always
```

### Step 5: Generate the Intermediate CA Key and CSR

```bash
cd /opt/ca/intermediate-ca

sudo openssl genrsa -aes256 -out private/intermediate.key.pem 4096
sudo chmod 400 private/intermediate.key.pem

sudo openssl req -config openssl.cnf -new -sha256 \
  -key private/intermediate.key.pem \
  -out csr/intermediate.csr.pem
```

### Step 6: Sign the Intermediate CA with the Root CA

The Root CA signs the Intermediate CA certificate, valid for 10 years. The
`pathlen:0` constraint in `v3_intermediate_ca` prevents the Intermediate CA
from signing further CA certificates below it.

```bash
cd /opt/ca/root-ca

sudo openssl ca -config openssl.cnf \
  -extensions v3_intermediate_ca \
  -days 3650 -notext -md sha256 \
  -in  ../intermediate-ca/csr/intermediate.csr.pem \
  -out ../intermediate-ca/certs/intermediate.cert.pem

sudo chmod 444 /opt/ca/intermediate-ca/certs/intermediate.cert.pem

# Verify the intermediate certificate
sudo openssl x509 -noout -text \
  -in /opt/ca/intermediate-ca/certs/intermediate.cert.pem

# Verify it chains correctly to the Root CA
sudo openssl verify -CAfile certs/ca.cert.pem \
  /opt/ca/intermediate-ca/certs/intermediate.cert.pem
```

### Step 7: Create the Certificate Chain Bundle

The chain bundle concatenates the Intermediate and Root certificates into a
single file. This is provided to clients during TLS handshakes so they can
verify the full trust chain without fetching certificates separately.

```bash
sudo cat \
  /opt/ca/intermediate-ca/certs/intermediate.cert.pem \
  /opt/ca/root-ca/certs/ca.cert.pem \
  | sudo tee /opt/ca/intermediate-ca/certs/ca-chain.cert.pem > /dev/null

sudo chmod 444 /opt/ca/intermediate-ca/certs/ca-chain.cert.pem
```

---

## Part 3 — Certificate Issuance

### Step 8: Issue a Server Certificate

A server certificate is issued for a specific domain using the `server_cert`
extension block, which sets `CA:FALSE`, restricts key usage to signing and
encryption, and sets the Extended Key Usage to `serverAuth`.

```bash
cd /opt/ca/intermediate-ca

sudo openssl genrsa \
  -out private/www.cybersec.ulb.ac.be.key.pem 2048
sudo chmod 400 private/www.cybersec.ulb.ac.be.key.pem

sudo openssl req -config openssl.cnf \
  -key private/www.cybersec.ulb.ac.be.key.pem \
  -new -sha256 \
  -out csr/www.cybersec.ulb.ac.be.csr.pem

sudo openssl ca -config openssl.cnf \
  -extensions server_cert -days 375 -notext -md sha256 \
  -in  csr/www.cybersec.ulb.ac.be.csr.pem \
  -out certs/www.cybersec.ulb.ac.be.cert.pem

sudo chmod 444 certs/www.cybersec.ulb.ac.be.cert.pem

# Verify
sudo openssl x509 -noout -text \
  -in certs/www.cybersec.ulb.ac.be.cert.pem

sudo openssl verify -CAfile certs/ca-chain.cert.pem \
  certs/www.cybersec.ulb.ac.be.cert.pem
```

### Step 9: Issue a Client Certificate

Client certificates authenticate individual users or devices to a server.
They use the `client_cert` extension block, which sets `clientAuth` and
`emailProtection` as the Extended Key Usage values.

```bash
sudo openssl genrsa \
  -out private/student.client.key.pem 2048
sudo chmod 400 private/student.client.key.pem

sudo openssl req -config openssl.cnf \
  -key private/student.client.key.pem \
  -new -sha256 \
  -out csr/student.client.csr.pem

# When prompted, set Common Name to: student@cybersec.ulb.ac.be

sudo openssl ca -config openssl.cnf \
  -extensions client_cert -days 375 -notext -md sha256 \
  -in  csr/student.client.csr.pem \
  -out certs/student.client.cert.pem

sudo chmod 444 certs/student.client.cert.pem

# Verify
sudo openssl verify -CAfile certs/ca-chain.cert.pem \
  certs/student.client.cert.pem
```

---

## Part 4 — Certificate Revocation

### Step 10: Generate the Initial CRL

A Certificate Revocation List (CRL) is a CA-signed list of certificates that
have been revoked before their expiry date. The initial CRL is empty but must
be generated and signed before it can be distributed.

```bash
cd /opt/ca/intermediate-ca

sudo openssl ca -config openssl.cnf -gencrl \
  -out crl/intermediate.crl.pem
```

The CRL is then converted from PEM (Base64 text) to DER (binary) format,
which is the standard format expected for web distribution:

```bash
sudo openssl crl -in crl/intermediate.crl.pem \
  -outform DER -out crl/intermediate.crl
```

### Step 11: Revoke a Certificate

To revoke a certificate, mark it as revoked in the CA database, then
regenerate and republish the CRL. Until the CRL is regenerated, clients
will not be aware of the revocation.

```bash
# Mark the certificate as revoked
sudo openssl ca -config openssl.cnf \
  -revoke certs/student.client.cert.pem

# Regenerate the CRL to include the revoked certificate
sudo openssl ca -config openssl.cnf -gencrl \
  -out crl/intermediate.crl.pem

# Verify the CRL contents
sudo openssl crl -in crl/intermediate.crl.pem -noout -text
```

### Step 12: Distribute the CRL

The CRL must be published at a publicly accessible URL. This URL is embedded
in the `crlDistributionPoints` extension of every certificate the
Intermediate CA issues. Clients download and check the CRL whenever they
validate a certificate.

```bash
# Copy the CRL to the web server's public directory
sudo mkdir -p /var/www/html/crl
sudo cp /opt/ca/intermediate-ca/crl/intermediate.crl \
  /var/www/html/crl/
sudo chmod 644 /var/www/html/crl/intermediate.crl

# Start Nginx to serve the CRL over HTTP
sudo systemctl start nginx || sudo service nginx start
sudo systemctl enable nginx || sudo update-rc.d nginx enable

# Test that the CRL is accessible
curl -I http://localhost/crl/intermediate.crl
```

> **Note:** The CRL must be regenerated and republished regularly, even if
> no certificates have been revoked, because CRLs have their own expiry date
> defined by `default_crl_days` in the configuration. An expired CRL will
> cause certificate validation to fail. Part 6 automates this.

---

## Part 5 — Mutual TLS (mTLS)

### Step 13: Configure Nginx for mTLS

Unlike standard TLS where only the server presents a certificate,
mTLS requires both parties to authenticate. The key directive is
`ssl_verify_client on`, which forces Nginx to request and validate
a client certificate during the TLS handshake.

Create the Nginx configuration:

```bash
sudo nano /etc/nginx/sites-available/mtls
```

```nginx
server {
    listen 443 ssl;
    server_name www.cybersec.ulb.ac.be;

    ssl_certificate     /opt/ca/intermediate-ca/certs/www.cybersec.ulb.ac.be.cert.pem;
    ssl_certificate_key /opt/ca/intermediate-ca/private/www.cybersec.ulb.ac.be.key.pem;

    ssl_client_certificate /opt/ca/intermediate-ca/certs/ca-chain.cert.pem;

    ssl_verify_client on;

    ssl_verify_depth 2;

    ssl_crl /opt/ca/intermediate-ca/crl/intermediate.crl.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_set_header X-Client-Cert-CN $ssl_client_s_dn_cn;
        proxy_set_header X-Client-Verify  $ssl_client_verify;

        root /var/www/html;
        index index.html;
    }
}

# Redirection HTTP → HTTPS
server {
    listen 80;
    server_name www.cybersec.ulb.ac.be;
    return 301 https://$host$request_uri;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/mtls \
           /etc/nginx/sites-enabled/mtls
sudo nginx -t
sudo systemctl reload nginx
```

### Step 14: Test mTLS

```bash
# Test 1 — without client certificate (should fail)
curl -v --cacert /opt/ca/root-ca/certs/ca.cert.pem \
  https://www.cybersec.ulb.ac.be/

# Test 2 — with client certificate (should succeed)
curl -v \
  --cacert /opt/ca/root-ca/certs/ca.cert.pem \
  --cert /opt/ca/intermediate-ca/certs/student.client.cert.pem \
  --key /opt/ca/intermediate-ca/private/student.client.key.pem \
  https://www.cybersec.ulb.ac.be/

# Test 3 — with revoked client certificate (should fail)
curl -v \
  --cacert /opt/ca/root-ca/certs/ca.cert.pem \
  --cert /opt/ca/intermediate-ca/certs/student.client.cert.pem \
  --key /opt/ca/intermediate-ca/private/student.client.key.pem \
  https://www.cybersec.ulb.ac.be/
```

---

## Part 6 — Automated Certificate Renewal

### Step 15: Renewal Strategy and Rationale

Modern PKI deployments cannot rely on manual renewal. Certificates expire
silently, and a service whose certificate has lapsed simply stops working
during the next TLS handshake. The renewal process must therefore be:

- **Automated:** triggered by a scheduler (cron), not by a human.
- **Threshold-based:** initiate renewal *before* expiry, not on the day of.
  The industry convention, used by Let's Encrypt's `certbot`, is to renew
  when fewer than 30 days of validity remain.
- **Idempotent:** the script runs every day, but actually performs a
  renewal only if needed.
- **Safe:** it backs up the existing certificate and key before any swap,
  and refuses to reload Nginx unless the new certificate verifies correctly.
- **Complete:** in an mTLS deployment, both **server** and **client**
  certificates must be tracked. An expired client certificate breaks the
  handshake exactly like an expired server certificate.

A second concern is the Certificate Revocation List itself. Even if no
certificates are revoked, the CRL has its own `nextUpdate` field driven by
`default_crl_days = 30` in the configuration. An expired CRL makes Nginx
reject every connection. The renewal infrastructure must therefore include
a periodic CRL refresh.

### Step 16: Handle the Encrypted Intermediate CA Key

The Intermediate CA private key generated in Step 5 is encrypted with
AES-256, which means any `openssl ca` invocation will prompt interactively
for a passphrase. This breaks unattended execution from cron. The cleanest
solution is to store the passphrase in a root-owned file with `0600`
permissions and pass it via OpenSSL's `-passin` option.

```bash
sudo nano /root/.intermediate.pass
# Type the Intermediate CA passphrase on a single line, then save.

sudo chmod 600 /root/.intermediate.pass
sudo chown root:root /root/.intermediate.pass
```

> **Security trade-off.** Keeping the passphrase on the same machine as the
> encrypted key reduces protection against a host compromise: an attacker
> with root on the server can read both files. For a lab project this is
> acceptable and documented as a known limitation. In a production
> deployment, the key would live in a Hardware Security Module (HSM) or
> behind a Key Management Service (KMS) such as HashiCorp Vault, AWS KMS,
> or Azure Key Vault, where the private key never leaves the secure boundary.

### Step 17: Create the Renewal Script

Place the script at `/opt/ca/scripts/renew-certs.sh`:

```bash
sudo mkdir -p /opt/ca/scripts /opt/ca/intermediate-ca/backup /var/log/ca
sudo nano /opt/ca/scripts/renew-certs.sh
```

```bash
#!/bin/bash
# =============================================================================
# /opt/ca/scripts/renew-certs.sh
# -----------------------------------------------------------------------------
# Automated renewal of end-entity certificates issued by the
# ULB Cybersecurity Lab Intermediate CA.
#
# The script is idempotent: it can run every day, but it only renews a
# certificate when its remaining validity falls below THRESHOLD_DAYS.
# Renewal involves generating a new key + CSR, signing with the Intermediate
# CA, verifying against the chain, atomically swapping the live files, and
# gracefully reloading Nginx.
# =============================================================================

set -euo pipefail

# ---------- Configuration ----------
INTERMEDIATE_DIR="/opt/ca/intermediate-ca"
CONFIG="${INTERMEDIATE_DIR}/openssl.cnf"
CERTS_DIR="${INTERMEDIATE_DIR}/certs"
KEYS_DIR="${INTERMEDIATE_DIR}/private"
CSR_DIR="${INTERMEDIATE_DIR}/csr"
BACKUP_DIR="${INTERMEDIATE_DIR}/backup"
LOG_FILE="/var/log/ca/renewal.log"
PASS_FILE="/root/.intermediate.pass"
THRESHOLD_DAYS=30
RENEW_DAYS=375


# Inventory of certificates to monitor:
#   "cert_path:key_path:extension_block:common_name"
CERTS=(
  "${CERTS_DIR}/www.cybersec.ulb.ac.be.cert.pem:${KEYS_DIR}/www.cybersec.ulb.ac.be.key.pem:server_cert:www.cybersec.ulb.ac.be"
  "${CERTS_DIR}/student.client.cert.pem:${KEYS_DIR}/student.client.key.pem:client_cert:student@cybersec.ulb.ac.be"
)

mkdir -p "${BACKUP_DIR}" "$(dirname "${LOG_FILE}")"

log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  echo -e "${msg}" | tee -a "${LOG_FILE}" > /dev/null
  echo -e "${msg}"
}

# -----------------------------------------------------------------------------
# Renew a single certificate
# -----------------------------------------------------------------------------
renew_cert() {
  local cert_path="$1"
  local key_path="$2"
  local extension="$3"
  local cn="$4"
  local base
  base="$(basename "${cert_path}" .cert.pem)"
  local stamp
  stamp="$(date '+%Y%m%d-%H%M%S')"

  local new_key="${KEYS_DIR}/${base}.renew.key.pem"
  local new_csr="${CSR_DIR}/${base}.renew.csr.pem"
  local new_cert="${CERTS_DIR}/${base}.renew.cert.pem"

  log "${YELLOW}Renewing ${cert_path} (CN=${cn}, ext=${extension})${NC}"

  # 1. Backup current artefacts before any change
  cp "${cert_path}" "${BACKUP_DIR}/${base}.cert.${stamp}.pem"
  cp "${key_path}"  "${BACKUP_DIR}/${base}.key.${stamp}.pem"

  # 2. Generate a fresh 2048-bit RSA key (rekey, not just re-issuance)
  openssl genrsa -out "${new_key}" 2048
  chmod 400 "${new_key}"

  # 3. Build a non-interactive CSR using -subj
  openssl req -config "${CONFIG}" -new -sha256 \
    -key "${new_key}" \
    -subj "/C=BE/ST=Brussels/L=Brussels/O=ULB Cybersecurity Lab/OU=IT Department/CN=${cn}" \
    -out "${new_csr}"

  # 4. Submit the CSR to the Intermediate CA (passphrase from file)
  openssl ca -batch -config "${CONFIG}" \
    -passin "file:${PASS_FILE}" \
    -extensions "${extension}" -days "${RENEW_DAYS}" -notext -md sha256 \
    -in  "${new_csr}" \
    -out "${new_cert}"

  # 5. Verify the new certificate against the chain BEFORE swapping
  if ! openssl verify -CAfile "${CERTS_DIR}/ca-chain.cert.pem" "${new_cert}" > /dev/null; then
    log "${RED}ERROR: verification failed for ${new_cert}. Aborting swap.${NC}"
    rm -f "${new_key}" "${new_csr}" "${new_cert}"
    return 1
  fi

  # 6. Atomic swap of the live files
  mv "${new_cert}" "${cert_path}"
  mv "${new_key}"  "${key_path}"
  chmod 444 "${cert_path}"
  chmod 400 "${key_path}"
  rm -f "${new_csr}"

  log "${GREEN}✓ Renewed ${cert_path}${NC}"
  return 0
}

# -----------------------------------------------------------------------------
# Main loop
# -----------------------------------------------------------------------------
log "${GREEN}=== Renewal run started ===${NC}"

needs_reload=0
threshold_seconds=$((THRESHOLD_DAYS * 86400))

for entry in "${CERTS[@]}"; do
  IFS=':' read -r cert_path key_path extension cn <<< "${entry}"

  if [[ ! -f "${cert_path}" ]]; then
    log "${YELLOW}WARN: ${cert_path} not found, skipping.${NC}"
    continue
  fi

  # openssl x509 -checkend N: exit 0 if cert is still valid in N seconds
  if openssl x509 -in "${cert_path}" -noout -checkend "${threshold_seconds}" > /dev/null; then
    not_after=$(openssl x509 -in "${cert_path}" -noout -enddate | cut -d= -f2)
    log "OK: ${cert_path} valid beyond ${THRESHOLD_DAYS} days (expires ${not_after})"
  else
    log "DUE: ${cert_path} expires within ${THRESHOLD_DAYS} days"
    if renew_cert "${cert_path}" "${key_path}" "${extension}" "${cn}"; then
      needs_reload=1
    fi
  fi
done

# -----------------------------------------------------------------------------
# Reload Nginx only if at least one renewal succeeded
# -----------------------------------------------------------------------------
if [[ "${needs_reload}" -eq 1 ]]; then
  log "Reloading Nginx..."
  if nginx -t >> "${LOG_FILE}" 2>&1; then
    systemctl reload nginx
    log "${GREEN}✓ Nginx reloaded${NC}"
  else
    log "${RED}ERROR: nginx -t failed. Manual intervention required.${NC}"
    exit 1
  fi
fi

log "${GREEN}=== Renewal run complete ===${NC}"
```

Lock it down so only root can read and execute it:

```bash
sudo chmod 700 /opt/ca/scripts/renew-certs.sh
sudo chown root:root /opt/ca/scripts/renew-certs.sh
```

### Step 18: Create the CRL Refresh Script

Place this script at `/opt/ca/scripts/refresh-crl.sh`. It regenerates the
CRL well before its 30-day expiry and republishes it for clients to fetch.

```bash
sudo nano /opt/ca/scripts/refresh-crl.sh
```

```bash
#!/bin/bash
# =============================================================================
# /opt/ca/scripts/refresh-crl.sh
# -----------------------------------------------------------------------------
# Regenerates and republishes the Intermediate CA Certificate Revocation List.
# Should run at least once per week so the CRL never approaches its
# nextUpdate boundary.
# =============================================================================

set -euo pipefail

INTERMEDIATE_DIR="/opt/ca/intermediate-ca"
CONFIG="${INTERMEDIATE_DIR}/openssl.cnf"
CRL_DIR="${INTERMEDIATE_DIR}/crl"
PUBLISH_DIR="/var/www/html/crl"
PASS_FILE="/root/.intermediate.pass"
LOG_FILE="/var/log/ca/crl.log"

mkdir -p "$(dirname "${LOG_FILE}")" "${PUBLISH_DIR}"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

log "=== CRL refresh started ==="

# Regenerate the CRL (PEM format)
openssl ca -batch -config "${CONFIG}" \
  -passin "file:${PASS_FILE}" \
  -gencrl \
  -out "${CRL_DIR}/intermediate.crl.pem"

# Convert to DER for web publication
openssl crl -in "${CRL_DIR}/intermediate.crl.pem" \
  -outform DER -out "${CRL_DIR}/intermediate.crl"

# Publish to the Nginx-served directory
cp "${CRL_DIR}/intermediate.crl" "${PUBLISH_DIR}/intermediate.crl"
chmod 644 "${PUBLISH_DIR}/intermediate.crl"

# Reload Nginx so the new CRL is loaded into memory
if nginx -t >> "${LOG_FILE}" 2>&1; then
  systemctl reload nginx
  log "Nginx reloaded with new CRL"
else
  log "ERROR: nginx -t failed after CRL refresh"
  exit 1
fi

log "=== CRL refresh complete ==="
```

```bash
sudo chmod 700 /opt/ca/scripts/refresh-crl.sh
sudo chown root:root /opt/ca/scripts/refresh-crl.sh
```

### Step 19: Schedule Everything with Cron

Both scripts must run as `root` because they touch the Intermediate CA key
and reload Nginx. Edit the root crontab:

```bash
sudo crontab -e
```

Add the following entries:

```cron
# Check certificates daily at 03:00 and renew anything within 30 days of expiry
0 3 * * * /opt/ca/scripts/renew-certs.sh >> /var/log/ca/cron.log 2>&1

# Refresh the CRL every Sunday at 04:00 (well before the 30-day expiry)
0 4 * * 0 /opt/ca/scripts/refresh-crl.sh >> /var/log/ca/cron.log 2>&1
```

Running daily is correct: the renewal script itself decides whether anything
actually needs renewing, so daily runs cost nothing on the days where all
certificates are still valid.

### Step 20: Force a Test Renewal

Waiting 345 days to find out whether the script works is not an option.
Force a renewal by temporarily raising `THRESHOLD_DAYS` so the existing
375-day certificates are seen as "due":

```bash
sudo nano /opt/ca/scripts/renew-certs.sh
# Change: THRESHOLD_DAYS=30
# To:     THRESHOLD_DAYS=400

sudo /opt/ca/scripts/renew-certs.sh

# Inspect the log
sudo tail -n 60 /var/log/ca/renewal.log
```

You should see, for each certificate:

1. A "DUE" entry indicating renewal was triggered.
2. A new line appended to `/opt/ca/intermediate-ca/index.txt`.
3. Old certificate and key copied to
   `/opt/ca/intermediate-ca/backup/<base>.cert.<timestamp>.pem`.
4. A new certificate at the original live path.
5. `Nginx reloaded` at the end.

Then verify the live certificate was actually swapped:

```bash
sudo openssl x509 -in /opt/ca/intermediate-ca/certs/www.cybersec.ulb.ac.be.cert.pem \
  -noout -dates -subject -issuer
```

The `notAfter` date should be approximately 375 days in the future, and the
serial number should be incremented compared to the previous certificate.

Run the mTLS curl tests from Step 14 to confirm the new certificate
participates correctly in the handshake.

Once everything works, reset the threshold:

```bash
sudo nano /opt/ca/scripts/renew-certs.sh
# Restore: THRESHOLD_DAYS=30
```

### Step 21: Force a Test CRL Refresh

Test the CRL refresh in the same way:

```bash
sudo /opt/ca/scripts/refresh-crl.sh
sudo tail -n 20 /var/log/ca/crl.log

# Confirm the new CRL is being served
curl -I http://localhost/crl/intermediate.crl

# Inspect the CRL contents and dates
sudo openssl crl \
  -in /opt/ca/intermediate-ca/crl/intermediate.crl.pem \
  -noout -lastupdate -nextupdate
```

The `nextUpdate` field should be roughly 30 days in the future.

### Step 22: Monitor and Audit

Two log files now record every PKI operation:

- `/var/log/ca/renewal.log` — every renewal decision and result.
- `/var/log/ca/crl.log` — every CRL refresh.
- `/var/log/ca/cron.log` — cron-level stdout/stderr.

Consider configuring `logrotate` to compress these logs monthly:

```bash
sudo nano /etc/logrotate.d/ca
```

```text
/var/log/ca/*.log {
    monthly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
```
