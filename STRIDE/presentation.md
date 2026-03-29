## Step 1 — Initial Topology (~1 min)

### 3 zones
- **Internet (untrusted)** : Remote Employee + Malicious PC + R1
- **Office network (trusted)** : PC-1 IT + PC-2 HR + R2
- **Server network** : Server-1 + Server-2 NGINX + R3

### Connections
- R1 ↔ R2 ↔ R3 via **RIPv2**
- Everyone can reach everyone

### Risks at this stage
- No VPN → plaintext traffic
- No firewall → no filtering
- No authentication → anyone can connect

---

## Step 2 — STRIDE Attacks (~2 min)

### A1 — Unauthorised access to servers *(Elevation of Privilege)*
- **What** : Malicious PC reaches NGINX servers via F4 (R1→R2→R3)
- **Why possible** : no firewall, no ACL
- **Impact** : full control over an internal server
- **L=4 / I=5 / Score 20 — Critical**
- **Mitigation** : firewall between office and servers, only PC-1 allowed

### A2 — IP Spoofing *(Spoofing)*
- **What** : Malicious PC forges the Remote Employee's IP (F1/F2)
- **Why possible** : no VPN, no identity verification
- **Impact** : access to office network undetected
- **L=4 / I=4 / Score 16 — High**
- **Mitigation** : VPN with certificates — a certificate cannot be forged

### A3 — Sniffing / Interception *(Information Disclosure)*
- **What** : passive traffic capture on F1 and F3 using Wireshark
- **Why possible** : all traffic flows over plaintext HTTP, no encryption
- **Why dangerous** : credentials, sessions, HR/IT data exposed — and undetectable
- **L=4 / I=4 / Score 16 — High**
- **Mitigation** : VPN encrypts F1 ; firewall reduces exposure on F3

### A4 — SYN/HTTP Flood *(Denial of Service)*
- **What** : flood of requests to saturate NGINX servers (F4/F7)
- **L=4 / I=3 / Score 12 — Elevated**
- **Mitigation** : NGINX rate limiting + SYN cookies (M2)

### A5 — Lateral Movement *(Elevation of Privilege)*
- **What** : a compromised server pivots towards the office network via F5
- **Precondition** : server already compromised (hence L=3)
- **L=3 / I=5 / Score 15 — High**
- **Mitigation** : firewall blocks any connection initiated from the servers

### Heatmap
- A1 alone in Critical → absolute priority
- A2 + A3 same High cell → both mitigated by the VPN
- A5 High but precondition → reduced likelihood
- A4 Elevated → will be addressed in M2 with the WAF

---

## Step 3 — Security Implementation (~1 min)

### Site-to-Site VPN
- Encrypted tunnel between R1 and R2
- Certificate-based authentication
- Remote Employee has a valid certificate → access granted
- Malicious PC has no certificate → rejected even if IP is forged
- Encrypts all traffic on F1 → mitigates A2 and A3

### Firewall (DMZ)
- Placed between office network and server network
- Why there? Servers can be compromised → isolated from office network (Zero Trust)
- **Rules:**
  - PC-1 (IT) → servers
  - PC-2 (HR) → blocked 
  - VPN traffic → blocked towards servers 
  - Servers → cannot initiate towards office (mitigates A5) 

---

## Step 4 — Demos (~6 min)

### Demo 1 — VPN : Remote Employee connected
- Remote Employee connects via VPN → ping PC-1/PC-2
- Wireshark → encrypted traffic, unreadable
- 👉 *"The tunnel works and encrypts communications"*

### Demo 2 — VPN : Malicious PC rejected
- Malicious PC attempts VPN connection → rejected
- 👉 *"No valid certificate = no access, even knowing the IP"*

### Demo 3 — Firewall : PC-1 reaches servers
- PC-1 → ping/curl Server-1 and Server-2
- 👉 *"IT Department has access as expected"*

### Demo 4 — Firewall : PC-2 blocked
- PC-2 → ping Server-1 → dropped
- 👉 *"HR has no access — principle of least privilege"*

### Demo 5 — Firewall : Server blocked towards office
- Server-1 → ping PC-1 → dropped
- 👉 *"Compromised server cannot pivot — A5 mitigated"*