# Certificate Authority, mTLS and Automated Renewal — Working Guide (Linux)

## Overview

This guide builds a complete two-tier PKI on Linux: a Root CA, an Intermediate
CA, server and client certificates, certificate revocation with a published
CRL, Mutual TLS (mTLS) with Nginx, optional browser trust, and automated
renewal driven by cron.


Assumptions: The demo hostname is `www.cybersec.ulb.ac.be`, resolved locally to `127.0.0.1`.

---

## Lab Environment Setup

```bash
sudo apt update
sudo apt install -y openssl nginx tree vim curl
```

Resolve the demo hostname to localhost so the tests and browser reach your own
server instead of the public internet:

```bash
echo "127.0.0.1 www.cybersec.ulb.ac.be" | sudo tee -a /etc/hosts
```

### Directory structure

```bash
sudo mkdir -p /opt/ca/{root-ca,intermediate-ca}
cd /opt/ca

sudo mkdir -p root-ca/{certs,crl,newcerts,private,csr}
sudo mkdir -p intermediate-ca/{certs,crl,newcerts,private,csr}

sudo chmod 700 root-ca/private intermediate-ca/private
sudo chmod 755 root-ca intermediate-ca

# Certificate databases and serial / CRL counters
sudo touch root-ca/index.txt intermediate-ca/index.txt
echo 1000 | sudo tee root-ca/serial
echo 1000 | sudo tee root-ca/crlnumber
echo 1000 | sudo tee intermediate-ca/serial
echo 1000 | sudo tee intermediate-ca/crlnumber

# Allow the Intermediate CA to re-issue a certificate with the same subject
# (renewal re-signs the same DN; without this, OpenSSL refuses the duplicate)
echo 'unique_subject = no' | sudo tee intermediate-ca/index.txt.attr
```


---

## Part 1 — Root Certificate Authority

### Step 1: Configure the Root CA

Create `/opt/ca/root-ca/openssl.cnf`:

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

### Step 2: Generate the Root CA private key

A 4096-bit RSA key encrypted with AES-256. You will be asked to choose a
passphrase — remember it; you need it whenever the Root CA signs something.

```bash
cd /opt/ca/root-ca
sudo openssl genrsa -aes256 -out private/ca.key.pem 4096
sudo chmod 400 private/ca.key.pem
```

### Step 3: Create the Root CA certificate

Self-signed, valid 20 years. The subject is supplied with `-subj` so the run is
deterministic (no interactive prompts). You will be asked for the Root key
passphrase.

```bash
sudo openssl req -config openssl.cnf \
  -key private/ca.key.pem \
  -new -x509 -days 7300 -sha256 -extensions v3_ca \
  -subj "/C=BE/ST=Brussels/L=Brussels/O=ULB Cybersecurity Lab/OU=Root CA/CN=ULB Cybersecurity Root CA/emailAddress=rootca@cybersec.ulb.ac.be" \
  -out certs/ca.cert.pem

sudo chmod 444 certs/ca.cert.pem
sudo openssl x509 -noout -text -in certs/ca.cert.pem | head -n 15
```

---

## Part 2 — Intermediate Certificate Authority

### Step 4: Configure the Intermediate CA

Create `/opt/ca/intermediate-ca/openssl.cnf`:

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
subjectAltName         = @alt_names

[ alt_names ]
DNS.1 = www.cybersec.ulb.ac.be
DNS.2 = cybersec.ulb.ac.be

[ client_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage               = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth, emailProtection

[ crl_ext ]
authorityKeyIdentifier = keyid:always
```


### Step 5: Generate the Intermediate CA key and CSR

```bash
cd /opt/ca/intermediate-ca
sudo openssl genrsa -aes256 -out private/intermediate.key.pem 4096
sudo chmod 400 private/intermediate.key.pem

sudo openssl req -config openssl.cnf -new -sha256 \
  -key private/intermediate.key.pem \
  -subj "/C=BE/ST=Brussels/L=Brussels/O=ULB Cybersecurity Lab/OU=Intermediate CA/CN=ULB Cybersecurity Intermediate CA/emailAddress=intermediate@cybersec.ulb.ac.be" \
  -out csr/intermediate.csr.pem
```

The Country, State and Organization match the Root CA (required by
`policy_strict`), while the Common Name is deliberately different from the Root.

### Step 6: Sign the Intermediate CA with the Root CA

Signed by the Root (enter the **Root** passphrase), valid 10 years. `-batch`
skips the interactive y/n prompts.

```bash
cd /opt/ca/root-ca
sudo openssl ca -batch -config openssl.cnf \
  -extensions v3_intermediate_ca -days 3650 -notext -md sha256 \
  -in  ../intermediate-ca/csr/intermediate.csr.pem \
  -out ../intermediate-ca/certs/intermediate.cert.pem

sudo chmod 444 /opt/ca/intermediate-ca/certs/intermediate.cert.pem
sudo openssl verify -CAfile certs/ca.cert.pem \
  /opt/ca/intermediate-ca/certs/intermediate.cert.pem
```

### Step 7: Create the certificate chain bundle

`ca-chain.cert.pem` = Intermediate + Root. Used by Nginx to verify client
certificates, and as a trust file for `curl`.

```bash
sudo cat \
  /opt/ca/intermediate-ca/certs/intermediate.cert.pem \
  /opt/ca/root-ca/certs/ca.cert.pem \
  | sudo tee /opt/ca/intermediate-ca/certs/ca-chain.cert.pem > /dev/null
sudo chmod 444 /opt/ca/intermediate-ca/certs/ca-chain.cert.pem
```

---

## Part 3 — Certificate Issuance

### Step 8: Issue the server certificate

The CN is the hostname; the SAN is added automatically from the config. Enter
the **Intermediate** passphrase when prompted.

```bash
cd /opt/ca/intermediate-ca

sudo openssl genrsa -out private/www.cybersec.ulb.ac.be.key.pem 2048
sudo chmod 400 private/www.cybersec.ulb.ac.be.key.pem

sudo openssl req -config openssl.cnf -new -sha256 \
  -key private/www.cybersec.ulb.ac.be.key.pem \
  -subj "/C=BE/ST=Brussels/L=Brussels/O=ULB Cybersecurity Lab/OU=IT Department/CN=www.cybersec.ulb.ac.be/emailAddress=server@cybersec.ulb.ac.be" \
  -out csr/www.cybersec.ulb.ac.be.csr.pem

sudo openssl ca -batch -config openssl.cnf \
  -extensions server_cert -days 375 -notext -md sha256 \
  -in  csr/www.cybersec.ulb.ac.be.csr.pem \
  -out certs/www.cybersec.ulb.ac.be.cert.pem
sudo chmod 444 certs/www.cybersec.ulb.ac.be.cert.pem

# Confirm the SAN is present
sudo openssl x509 -noout -text -in certs/www.cybersec.ulb.ac.be.cert.pem \
  | grep -A1 "Subject Alternative Name"
```

Build the **fullchain** (leaf + intermediate). Nginx must serve this, not the
bare leaf, or clients cannot link the server cert to the Root.

```bash
sudo cat certs/www.cybersec.ulb.ac.be.cert.pem certs/intermediate.cert.pem \
  | sudo tee certs/www.cybersec.ulb.ac.be.fullchain.cert.pem > /dev/null
sudo chmod 444 certs/www.cybersec.ulb.ac.be.fullchain.cert.pem
```



### Step 9: Issue two client certificates

Two certs: `prof.client` stays valid (used for the "should succeed" test) and
`student.client` will be revoked (the "should fail" test). Enter the
Intermediate passphrase for each signing.

```bash
# Valid client (prof)
sudo openssl genrsa -out private/prof.client.key.pem 2048
sudo chmod 400 private/prof.client.key.pem
sudo openssl req -config openssl.cnf -new -sha256 \
  -key private/prof.client.key.pem \
  -subj "/C=BE/ST=Brussels/L=Brussels/O=ULB Cybersecurity Lab/OU=IT Department/CN=prof@cybersec.ulb.ac.be/emailAddress=prof@cybersec.ulb.ac.be" \
  -out csr/prof.client.csr.pem
sudo openssl ca -batch -config openssl.cnf \
  -extensions client_cert -days 375 -notext -md sha256 \
  -in csr/prof.client.csr.pem -out certs/prof.client.cert.pem
sudo chmod 444 certs/prof.client.cert.pem

# Client to be revoked (student)
sudo openssl genrsa -out private/student.client.key.pem 2048
sudo chmod 400 private/student.client.key.pem
sudo openssl req -config openssl.cnf -new -sha256 \
  -key private/student.client.key.pem \
  -subj "/C=BE/ST=Brussels/L=Brussels/O=ULB Cybersecurity Lab/OU=IT Department/CN=student@cybersec.ulb.ac.be/emailAddress=student@cybersec.ulb.ac.be" \
  -out csr/student.client.csr.pem
sudo openssl ca -batch -config openssl.cnf \
  -extensions client_cert -days 375 -notext -md sha256 \
  -in csr/student.client.csr.pem -out certs/student.client.cert.pem
sudo chmod 444 certs/student.client.cert.pem

sudo openssl verify -CAfile certs/ca-chain.cert.pem certs/prof.client.cert.pem
sudo openssl verify -CAfile certs/ca-chain.cert.pem certs/student.client.cert.pem
```


---

## Part 4 — Certificate Revocation

### Step 10: Generate the initial Intermediate CRL

```bash
cd /opt/ca/intermediate-ca
sudo openssl ca -batch -config openssl.cnf -gencrl -out crl/intermediate.crl.pem
```

### Step 11: Revoke the student certificate and regenerate the CRL

```bash
sudo openssl ca -batch -config openssl.cnf -revoke certs/student.client.cert.pem
sudo openssl ca -batch -config openssl.cnf -gencrl -out crl/intermediate.crl.pem
sudo openssl crl -in crl/intermediate.crl.pem -noout -text | head -n 20
```

### Step 12: Generate the Root CRL and build the combined CRL

```bash
# Root CRL (covers the Intermediate). Enter the ROOT passphrase.
cd /opt/ca/root-ca
sudo openssl ca -batch -config openssl.cnf -gencrl -out crl/ca.crl.pem

# Combined CRL that Nginx will read (Intermediate + Root)
sudo cat \
  /opt/ca/intermediate-ca/crl/intermediate.crl.pem \
  /opt/ca/root-ca/crl/ca.crl.pem \
  | sudo tee /opt/ca/intermediate-ca/crl/chain.crl.pem > /dev/null
```



### Step 13: Publish the CRL over HTTP

CRLs are distributed over plain HTTP by design (they are CA-signed and public,
and HTTPS would create a validation loop).

```bash
sudo openssl crl -in /opt/ca/intermediate-ca/crl/intermediate.crl.pem \
  -outform DER -out /opt/ca/intermediate-ca/crl/intermediate.crl

sudo mkdir -p /var/www/html/crl
sudo cp /opt/ca/intermediate-ca/crl/intermediate.crl /var/www/html/crl/
sudo chmod 644 /var/www/html/crl/intermediate.crl

sudo systemctl enable --now nginx
curl -I http://localhost/crl/intermediate.crl
```

---

## Part 5 — Mutual TLS (mTLS)

### Step 14: Create a landing page

```bash
echo "<h1>mTLS authenticated — ULB Cybersecurity Lab</h1>" | sudo tee /var/www/html/index.html
```

### Step 15: Configure Nginx for mTLS

```bash
sudo nano /etc/nginx/sites-available/mtls
```

```nginx
server {
    listen 443 ssl;
    server_name www.cybersec.ulb.ac.be;

    ssl_certificate     /opt/ca/intermediate-ca/certs/www.cybersec.ulb.ac.be.fullchain.cert.pem;
    ssl_certificate_key /opt/ca/intermediate-ca/private/www.cybersec.ulb.ac.be.key.pem;

    ssl_client_certificate /opt/ca/intermediate-ca/certs/ca-chain.cert.pem;
    ssl_verify_client on;
    ssl_verify_depth 2;
    ssl_crl /opt/ca/intermediate-ca/crl/chain.crl.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        add_header X-Client-DN     $ssl_client_s_dn   always;
        add_header X-Client-Verify $ssl_client_verify always;

        root  /var/www/html;
        index index.html;
    }
}

# HTTP -> HTTPS redirect
server {
    listen 80;
    server_name www.cybersec.ulb.ac.be;
    return 301 https://$host$request_uri;
}
```


Enable and reload:

```bash
sudo ln -s /etc/nginx/sites-available/mtls /etc/nginx/sites-enabled/mtls
sudo nginx -t && sudo systemctl reload nginx
```

### Step 16: Test mTLS

The client private keys live in the `700` `private/` directory, so the tests
that present a client certificate must run with `sudo`.

```bash
# Test 1 — no client cert -> 400 "No required SSL certificate was sent"
sudo curl -sI --cacert /opt/ca/root-ca/certs/ca.cert.pem \
  https://www.cybersec.ulb.ac.be/ | head -1

# Test 2 — valid client cert (prof) -> 200 OK
sudo curl -sI --cacert /opt/ca/root-ca/certs/ca.cert.pem \
  --cert /opt/ca/intermediate-ca/certs/prof.client.cert.pem \
  --key  /opt/ca/intermediate-ca/private/prof.client.key.pem \
  https://www.cybersec.ulb.ac.be/ | head -1

# Test 3 — revoked client cert (student) -> 400 "The SSL certificate error"
sudo curl -sI --cacert /opt/ca/root-ca/certs/ca.cert.pem \
  --cert /opt/ca/intermediate-ca/certs/student.client.cert.pem \
  --key  /opt/ca/intermediate-ca/private/student.client.key.pem \
  https://www.cybersec.ulb.ac.be/ | head -1
```

Expected: `400` (no cert), `200 OK` (valid), `400` (revoked). Drop `-I` for `-v`
to watch the full handshake.

---

## Part 6 — Browser Trust and Testing (optional)

To demonstrate mTLS in Chrome/Chromium on Linux.

### Step 17: Package the valid client certificate

```bash
cd /opt/ca/intermediate-ca
sudo openssl pkcs12 -export \
  -inkey private/prof.client.key.pem \
  -in    certs/prof.client.cert.pem \
  -certfile certs/ca-chain.cert.pem \
  -out   prof.client.p12
# set an export password — you re-enter it on import
sudo cp prof.client.p12 ~/ && sudo chown "$USER:$USER" ~/prof.client.p12
```

### Step 18: Trust the Root CA and import the client cert

Run these as your normal user (no `sudo`), then fully restart the browser.

```bash
sudo apt install -y libnss3-tools
mkdir -p ~/.pki/nssdb

certutil -d sql:"$HOME/.pki/nssdb" -A -t "C,," -n "ULB Cybersecurity Root CA" \
  -i /opt/ca/root-ca/certs/ca.cert.pem

pk12util -d sql:"$HOME/.pki/nssdb" -i ~/prof.client.p12
```

GUI alternative: `chrome://settings/certificates` → Authorities → Import
`ca.cert.pem` (trust for identifying websites); then Your Certificates → Import
`prof.client.p12`.

### Step 19: Open it

Visit `https://www.cybersec.ulb.ac.be/`. The browser prompts for a client
certificate — choose `prof@cybersec.ulb.ac.be` — and the page loads. Click the
padlock → Certificate to inspect the chain and the SAN.

---

## Part 7 — Automated Renewal

### Step 20: Store the Intermediate passphrase

The renewal and CRL scripts run unattended, so the Intermediate passphrase is
read from a root-only file.

```bash
sudo bash -c 'read -rsp "Intermediate passphrase: " p && echo "$p" > /root/.intermediate.pass && echo'
sudo chmod 600 /root/.intermediate.pass && sudo chown root:root /root/.intermediate.pass
```

> Security trade-off: the passphrase sits next to the key, so root on this host
> can use the key. Acceptable for a lab; in production the key would live in an
> HSM or KMS (Vault, AWS KMS, Azure Key Vault).

### Step 21: Create the renewal script

```bash
sudo mkdir -p /opt/ca/scripts /opt/ca/intermediate-ca/backup /var/log/ca
sudo tee /opt/ca/scripts/renew-certs.sh > /dev/null <<'SCRIPT'
#!/bin/bash
set -euo pipefail

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'

INTERMEDIATE_DIR="/opt/ca/intermediate-ca"
CONFIG="${INTERMEDIATE_DIR}/openssl.cnf"
CERTS_DIR="${INTERMEDIATE_DIR}/certs"
KEYS_DIR="${INTERMEDIATE_DIR}/private"
CSR_DIR="${INTERMEDIATE_DIR}/csr"
BACKUP_DIR="${INTERMEDIATE_DIR}/backup"
LOG_FILE="/var/log/ca/renewal.log"
PASS_FILE="/root/.intermediate.pass"
THRESHOLD_DAYS="${THRESHOLD_DAYS:-30}"
RENEW_DAYS=375

CERTS=(
  "${CERTS_DIR}/www.cybersec.ulb.ac.be.cert.pem:${KEYS_DIR}/www.cybersec.ulb.ac.be.key.pem:server_cert:www.cybersec.ulb.ac.be"
  "${CERTS_DIR}/prof.client.cert.pem:${KEYS_DIR}/prof.client.key.pem:client_cert:prof@cybersec.ulb.ac.be"
)

mkdir -p "${BACKUP_DIR}" "$(dirname "${LOG_FILE}")"

log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  echo -e "${msg}" | tee -a "${LOG_FILE}" > /dev/null
  echo -e "${msg}"
}

renew_cert() {
  local cert_path="$1" key_path="$2" extension="$3" cn="$4"
  local base; base="$(basename "${cert_path}" .cert.pem)"
  local stamp; stamp="$(date '+%Y%m%d-%H%M%S')"
  local new_key="${KEYS_DIR}/${base}.renew.key.pem"
  local new_csr="${CSR_DIR}/${base}.renew.csr.pem"
  local new_cert="${CERTS_DIR}/${base}.renew.cert.pem"

  log "${YELLOW}Renewing ${cert_path} (CN=${cn})${NC}"
  cp "${cert_path}" "${BACKUP_DIR}/${base}.cert.${stamp}.pem"
  cp "${key_path}"  "${BACKUP_DIR}/${base}.key.${stamp}.pem"

  openssl genrsa -out "${new_key}" 2048
  chmod 400 "${new_key}"
  openssl req -config "${CONFIG}" -new -sha256 -key "${new_key}" \
    -subj "/C=BE/ST=Brussels/L=Brussels/O=ULB Cybersecurity Lab/OU=IT Department/CN=${cn}" \
    -out "${new_csr}"

  openssl ca -batch -config "${CONFIG}" -passin "file:${PASS_FILE}" \
    -extensions "${extension}" -days "${RENEW_DAYS}" -notext -md sha256 \
    -in "${new_csr}" -out "${new_cert}"

  if ! openssl verify -CAfile "${CERTS_DIR}/ca-chain.cert.pem" "${new_cert}" > /dev/null; then
    log "${RED}ERROR: verification failed for ${new_cert}. Aborting.${NC}"
    rm -f "${new_key}" "${new_csr}" "${new_cert}"; return 1
  fi

  mv "${new_cert}" "${cert_path}"; mv "${new_key}" "${key_path}"
  chmod 444 "${cert_path}"; chmod 400 "${key_path}"; rm -f "${new_csr}"

  # Rebuild the fullchain (server cert) so Nginx serves the new leaf + key
  if [[ -f "${CERTS_DIR}/${base}.fullchain.cert.pem" ]]; then
    rm -f "${CERTS_DIR}/${base}.fullchain.cert.pem"
    cat "${cert_path}" "${CERTS_DIR}/intermediate.cert.pem" \
      > "${CERTS_DIR}/${base}.fullchain.cert.pem"
    chmod 444 "${CERTS_DIR}/${base}.fullchain.cert.pem"
  fi

  log "${GREEN}Renewed ${cert_path}${NC}"; return 0
}

log "${GREEN}=== Renewal run started ===${NC}"
needs_reload=0
threshold_seconds=$((THRESHOLD_DAYS * 86400))

for entry in "${CERTS[@]}"; do
  IFS=':' read -r cert_path key_path extension cn <<< "${entry}"
  if [[ ! -f "${cert_path}" ]]; then
    log "${YELLOW}WARN: ${cert_path} not found, skipping.${NC}"; continue
  fi
  if openssl x509 -in "${cert_path}" -noout -checkend "${threshold_seconds}" > /dev/null; then
    not_after=$(openssl x509 -in "${cert_path}" -noout -enddate | cut -d= -f2)
    log "OK: ${cert_path} valid beyond ${THRESHOLD_DAYS} days (expires ${not_after})"
  else
    log "DUE: ${cert_path} expires within ${THRESHOLD_DAYS} days"
    if renew_cert "${cert_path}" "${key_path}" "${extension}" "${cn}"; then needs_reload=1; fi
  fi
done

if [[ "${needs_reload}" -eq 1 ]]; then
  log "Reloading Nginx..."
  if nginx -t >> "${LOG_FILE}" 2>&1; then
    systemctl reload nginx; log "${GREEN}Nginx reloaded${NC}"
  else
    log "${RED}ERROR: nginx -t failed.${NC}"; exit 1
  fi
fi
log "${GREEN}=== Renewal run complete ===${NC}"
SCRIPT

sudo chmod 700 /opt/ca/scripts/renew-certs.sh
sudo chown root:root /opt/ca/scripts/renew-certs.sh
```


### Step 22: Create the CRL refresh script

```bash
sudo tee /opt/ca/scripts/refresh-crl.sh > /dev/null <<'SCRIPT'
#!/bin/bash
set -euo pipefail

INTERMEDIATE_DIR="/opt/ca/intermediate-ca"
CONFIG="${INTERMEDIATE_DIR}/openssl.cnf"
CRL_DIR="${INTERMEDIATE_DIR}/crl"
ROOT_CRL="/opt/ca/root-ca/crl/ca.crl.pem"
PUBLISH_DIR="/var/www/html/crl"
PASS_FILE="/root/.intermediate.pass"
LOG_FILE="/var/log/ca/crl.log"

mkdir -p "$(dirname "${LOG_FILE}")" "${PUBLISH_DIR}"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"; }

log "=== CRL refresh started ==="
openssl ca -batch -config "${CONFIG}" -passin "file:${PASS_FILE}" \
  -gencrl -out "${CRL_DIR}/intermediate.crl.pem"
openssl crl -in "${CRL_DIR}/intermediate.crl.pem" -outform DER -out "${CRL_DIR}/intermediate.crl"
cp "${CRL_DIR}/intermediate.crl" "${PUBLISH_DIR}/intermediate.crl"
chmod 644 "${PUBLISH_DIR}/intermediate.crl"

# Rebuild the combined CRL that Nginx actually reads (Intermediate + Root)
cat "${CRL_DIR}/intermediate.crl.pem" "${ROOT_CRL}" > "${CRL_DIR}/chain.crl.pem"

if nginx -t >> "${LOG_FILE}" 2>&1; then
  systemctl reload nginx; log "Nginx reloaded with refreshed CRL"
else
  log "ERROR: nginx -t failed after CRL refresh"; exit 1
fi
log "=== CRL refresh complete ==="
SCRIPT

sudo chmod 700 /opt/ca/scripts/refresh-crl.sh
sudo chown root:root /opt/ca/scripts/refresh-crl.sh
```


> Note: the Root CRL (`ca.crl.pem`) also has a 30-day lifetime but is reused
> here. For a long-running deployment, regenerate it periodically too (it
> requires the Root passphrase). For a lab/demo it is valid throughout.

### Step 23: Schedule with cron

```bash
( sudo crontab -l 2>/dev/null; \
  echo '0 3 * * * /opt/ca/scripts/renew-certs.sh  >> /var/log/ca/cron.log 2>&1'; \
  echo '0 4 * * 0 /opt/ca/scripts/refresh-crl.sh >> /var/log/ca/cron.log 2>&1' ) | sudo crontab -
```

### Step 24: Force a test renewal

`THRESHOLD_DAYS=400` makes the 375-day certs look "due." Because it is passed in
the environment, the live default (30) is untouched — nothing to revert.

```bash
sudo cp -r /opt/ca/intermediate-ca/certs /opt/ca/intermediate-ca/certs.bak
sudo env THRESHOLD_DAYS=400 /opt/ca/scripts/renew-certs.sh
sudo tail -n 40 /var/log/ca/renewal.log

# SAN survived the renewal?
sudo openssl x509 -noout -text -in /opt/ca/intermediate-ca/certs/www.cybersec.ulb.ac.be.cert.pem \
  | grep -A1 "Subject Alternative Name"

# mTLS still works after renewal?
sudo curl -sI --cacert /opt/ca/root-ca/certs/ca.cert.pem \
  --cert /opt/ca/intermediate-ca/certs/prof.client.cert.pem \
  --key  /opt/ca/intermediate-ca/private/prof.client.key.pem \
  https://www.cybersec.ulb.ac.be/ | head -1
```

Expect `DUE`/`Renewed` lines, the SAN still present, and `HTTP/1.1 200 OK`.

### Step 25: Force a test CRL refresh

```bash
sudo /opt/ca/scripts/refresh-crl.sh
sudo tail -n 20 /var/log/ca/crl.log
sudo openssl crl -in /opt/ca/intermediate-ca/crl/intermediate.crl.pem \
  -noout -lastupdate -nextupdate
```

### Step 26: Log rotation

```bash
sudo tee /etc/logrotate.d/ca > /dev/null <<'EOF'
/var/log/ca/*.log {
    monthly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
EOF
```

---



## Teardown 

```bash
sudo crontab -l 2>/dev/null | grep -vE 'renew-certs\.sh|refresh-crl\.sh' | sudo crontab -
sudo rm -f /etc/nginx/sites-enabled/mtls /etc/nginx/sites-available/mtls
sudo systemctl reload nginx 2>/dev/null || true
sudo rm -rf /opt/ca /var/www/html/crl /var/log/ca /etc/logrotate.d/ca
sudo rm -f /root/.intermediate.pass
sudo sed -i '/www\.cybersec\.ulb\.ac\.be/d' /etc/hosts
certutil -d sql:"$HOME/.pki/nssdb" -D -n "ULB Cybersecurity Root CA" 2>/dev/null || true
```
