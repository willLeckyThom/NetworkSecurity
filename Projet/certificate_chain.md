# Certificate Authority Implementation and Deployment Guide for Linux

## Overview

This guide demonstrates the practical implementation of a Certificate Authority
(CA) infrastructure on Linux. It covers the creation of a Root CA, an
Intermediate CA, the issuance of server and client certificates, and the
management of certificate revocation.

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
> cause certificate validation to fail.

---

## Part 5 — Mutual TLS (mTLS)

### Step 13: Configure Nginx for mTLS

Unlike standard TLS where only the server presents a certificate,
mTLS requires both parties to authenticate. The key directive is
`ssl_verify_client on`, which forces Nginx to request and validate
a client certificate during the TLS handshake.

Create the Nginx configuration:

    sudo nano /etc/nginx/sites-available/mtls


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

    sudo ln -s /etc/nginx/sites-available/mtls \
               /etc/nginx/sites-enabled/mtls
    sudo nginx -t
    sudo systemctl reload nginx

### Step 14: Test mTLS

# Test 1 — without client certificate
    curl -v --cacert /opt/ca/root-ca/certs/ca.cert.pem \
      https://www.cybersec.ulb.ac.be/

# Test 2 — with client certificate
    curl -v \
      --cacert /opt/ca/root-ca/certs/ca.cert.pem \
      --cert /opt/ca/intermediate-ca/certs/student.client.cert.pem \
      --key /opt/ca/intermediate-ca/private/student.client.key.pem \
      https://www.cybersec.ulb.ac.be/
# Test 3 — with revoked client certificate

curl -v \
  --cacert /opt/ca/root-ca/certs/ca.cert.pem \
  --cert /opt/ca/intermediate-ca/certs/student.client.cert.pem \
  --key /opt/ca/intermediate-ca/private/student.client.key.pem \
  https://www.cybersec.ulb.ac.be/
