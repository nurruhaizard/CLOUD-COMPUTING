# CLOUD-COMPUTING: IKB42603 Cloud Computing Security Essentials

**Universiti Kuala Lumpur (UniKL MIIT)**  
**Student Name:** IWANI IZZATI (NUR IWANI IZZATI BINTI RUHAIZARD)  
**Student ID:** 52215225392D  
**Course Code:** IKB42603 Cloud Computing Security Essentials  
**Program:** Bachelor of Information Technology / Computer Science (Information Security / Cloud Computing)  
**Lecturer / Instructor:** Ms Adani / Prof. Dr. Shahrulniza Musa  

---

## Laboratory Assignments Directory

| Lab Module | Title | Primary Security Domains | Report Link | Evidence Directory |
| :--- | :--- | :--- | :---: | :---: |
| **Lab 1** | Cloud Account Security, Identity & Access Management | Identity Governance, Least Privilege, LocalStack IAM, Credential Hygiene, Kubernetes RBAC | [LAB 1 Report](./LAB%201/LAB%201%20IWANI%20IZZATI.md) | [LAB 1 Evidence](./LAB%201/Evidence/) |
| **Lab 2** | Secure Isolation & Multi-Tenancy | Compute, Network, Storage Isolation, NetworkPolicy, RBAC, Data Remanence | [LAB 2 Report](./LAB%202/LAB%202%20IWANI%20IZZATI.md) | [LAB 2 EVIDENCE](./LAB%202/EVIDENCE/) |
| **Lab 3** | Data Protection: Encryption & Key Management | Symmetric (AES), Asymmetric (RSA), TLS, Envelope Encryption, KMS, Cryptographic Erasure, Hash Chaining | [LAB 3 Report](./LAB%203/LAB%203%20IWANI%20IZZATI.md) | [LAB 3 EVIDENCE](./LAB%203/EVIDENCE/) |
| **Lab 4** | Access Control & Network Security | AuthN vs AuthZ, MFA TOTP, Kubernetes RBAC, Three-Tier Segmentation, Default-Deny, Container Hardening | [LAB 4 Report](./LAB%204/LAB%204%20IWANI%20IZZATI.md) | [LAB 4 EVIDENCE](./LAB%204/EVIDENCE/) |
| **Lab 5** | Monitoring, Logging & Incident Detection | Telemetry, CloudWatch, Hash-Chained Logs, SIEM Correlation, Incident Response | [LAB 5 Report](./LAB%205/LAB%205%20IWANI%20IZZATI.md) | [LAB 5 Evidence](./LAB%205/Evidence/) |

---

## Lab 1 Overview: Cloud Account Security, Identity & Access Management (LocalStack IAM & Kubernetes RBAC)

- 📄 **Full Report:** [LAB 1 IWANI IZZATI.md](./LAB%201/LAB%201%20IWANI%20IZZATI.md)
- 📁 **Evidence Repository:** [LAB 1/Evidence/](./LAB%201/Evidence/)
- 📘 **Lab Guide:** [IKB42603_Lab1_Account_Security_and_IAM.pdf](./LAB%201/IKB42603_Lab1_Account_Security_and_IAM.pdf)

### Lab 1 Execution Matrix

| Step / Task | Description | Security Dimension | Status |
| :--- | :--- | :---: | :---: |
| **Setup** | Stand up LocalStack IAM/STS container & initial caller-identity check | Environment Setup | Completed |
| **Task 1** | Map Cloud Identity Landscape (Root, IAM User, Policy, Group, Role) | Identity Governance | Completed |
| **Task 2** | Least-Privilege Admin (Admins group, AdministratorAccess, CloudAdmin_NADYA) | Privilege Delegation | Completed |
| **Task 3** | Scoped Policy Enforcement (Analyst_NADYA, AmazonS3ReadOnlyAccess, blast-radius reduction) | Least Privilege | Completed |
| **Task 4** | Credential Hygiene & Access Keys (Key generation, metadata inspection, status deactivation) | Credential Lifecycle | Completed |
| **Task 5** | Separate Environments with Namespaces (dev and prod namespace isolation in kind cluster) | Multi-Tenancy | Completed |
| **Task 6** | Define a Role and Bind It (dev-user ServiceAccount, pod-reader Role, dev-user-binding) | Kubernetes RBAC | Completed |
| **Task 7** | Test Access Control Boundary (kubectl auth can-i evaluation: dev allowed, delete & prod denied) | AuthN vs AuthZ Enforcement | Completed |


---

## Lab 2 Overview: Secure Isolation & Multi-Tenancy (Docker & Kubernetes)

- 📄 **Full Report:** [LAB 2 IWANI IZZATI.md](./LAB%202/LAB%202%20IWANI%20IZZATI.md)
- 📁 **Evidence Repository:** [LAB 2/EVIDENCE/](./LAB%202/EVIDENCE/)
- 📘 **Lab Guide:** [IKB42603_Lab2_Secure_Isolation_and_Multitenancy.pdf](./LAB%202/IKB42603_Lab2_Secure_Isolation_and_Multitenancy.pdf)

### Lab 2 Execution Matrix

| Step / Task | Description | Dimension | Status |
| :--- | :--- | :---: | :---: |
| **Setup** | Deploy kind cluster with disableDefaultCNI: true & Project Calico CNI | Network / Compute | Completed |
| **Task 1** | Two Tenants on One Cluster (tenant-a & tenant-b namespaces, Nginx services) | Compute | Completed |
| **Task 2** | Observe Default-Open Risk (Cross-tenant HTTP probe, HTTP 200 response) | Network | Completed |
| **Task 3** | Contain the Noisy Neighbour (Apply ResourceQuota for CPU, memory, and pods) | Compute | Completed |
| **Task 4** | Default-Deny Network Isolation (default-deny-ingress NetworkPolicy & verification) | Network | Completed |
| **Task 5** | Storage & Secret Isolation (Per-tenant Secrets & RBAC ServiceAccount verification) | Storage / Identity | Completed |
| **Task 6** | Data Remanence & Secure Deletion (rm remanence scan vs. dd secure zeroing) | Storage | Completed |

---

## Lab 3 Overview: Data Protection: Encryption & Key Management (OpenSSL & LocalStack KMS)

- 📄 **Full Report:** [LAB 3 IWANI IZZATI.md](./LAB%203/LAB%203%20IWANI%20IZZATI.md)
- 📁 **Evidence Repository:** [LAB 3/EVIDENCE/](./LAB%203/EVIDENCE/)
- 📘 **Lab Guide:** [IKB42603_Lab3_Encryption_and_Key_Management.pdf](./LAB%203/IKB42603_Lab3_Encryption_and_Key_Management.pdf)

### Lab 3 Execution Matrix

| Step / Task | Description | Security Domain | Status |
| :--- | :--- | :---: | :---: |
| **Task 1** | Symmetric Encryption (AES-256-CBC with PBKDF2 salt & decryption match confirmation) | Data at Rest | Completed |
| **Task 2** | Asymmetric Encryption & Digital Signatures (RSA-2048 keypair, encryption & verified digital signature) | Confidentiality & Authenticity | Completed |
| **Task 3** | Encryption in Transit (TLS over HTTPS with self-signed X.509 certificate on Docker Nginx) | Data in Flight | Completed |
| **Task 4** | Create and Use a KMS Master Key (LocalStack KMS CMK creation & direct secret encryption) | Key Management | Completed |
| **Task 5** | Envelope Encryption (KMS Data Encryption Key generation, local AES encryption & plaintext purging) | Scalable Hybrid Cryptography | Completed |
| **Task 6** | Per-Tenant Keys & Cryptographic Erasure (Multi-tenant CMKs, key deletion & provable decryption failure) | Multi-Tenancy & Data Sanitization | Completed |
| **Task 7** | Integrity & Tamper-Evidence (SHA-256 file fingerprinting, tamper detection & forward hash chain) | Data Integrity & Audit Trails | Completed |

---

## Lab 4 Overview: Access Control & Network Security (Docker & Kubernetes)

- 📄 **Full Report:** [LAB 4 IWANI IZZATI.md](./LAB%204/LAB%204%20IWANI%20IZZATI.md)
- 📁 **Evidence Repository:** [LAB 4/EVIDENCE/](./LAB%204/EVIDENCE/)
- 📘 **Lab Guide:** [IKB42603_Lab4_Access_Control_and_Network_Security.pdf](./LAB%204/IKB42603_Lab4_Access_Control_and_Network_Security.pdf)

### Lab 4 Execution Matrix

| Step / Task | Description | Security Dimension | Status |
| :--- | :--- | :---: | :---: |
| **Task 1** | Authentication: A Password-Protected Service (Nginx HTTP Basic Auth with htpasswd) | Authentication (AuthN) | Completed |
| **Task 2** | Add a Second Factor (MFA / TOTP RFC 6238 generation & validation via oathtool) | Multi-Factor Identity | Completed |
| **Task 3** | Authorization: RBAC Roles (Kubernetes dev-role, dev-rb RoleBinding, least-privilege checks) | Authorization (AuthZ) | Completed |
| **Task 4** | Network Segmentation (Three-Tier: web on frontend-net, app dual-homed, db on backend-net) | Network Micro-Segmentation | Completed |
| **Task 5** | Host Firewall Rules (Default-Deny policy INPUT DROP with port 443 allow via iptables) | Host Perimeter Security | Completed |
| **Task 6** | Container Hardening & Vulnerability Scanning (nginx-unprivileged, non-root, read-only, cap-drop=ALL, Trivy CVE audit) | Workload Hardening & Supply Chain | Completed |

---

## Lab 5 Overview: Monitoring, Logging & Incident Detection

- 📄 **Full Report:** [LAB 5 IWANI IZZATI.md](./LAB%205/LAB%205%20IWANI%20IZZATI.md)
- 📁 **Evidence Repository:** [LAB 5/Evidence/](./LAB%205/Evidence/)
- 📘 **Lab Guide:** [IKB42603_Lab5_Monitoring_Logging_and_Incident_Detection.pdf](./LAB%205/IKB42603_Lab5_Monitoring_Logging_and_Incident_Detection.pdf)

### Lab 5 Execution Matrix

| Task | Description | Status |
| :--- | :--- | :---: |
| **Task 1** | Generate Application Logs (auth.log) | Completed |
| **Task 2** | Centralise Logs (Ship to AWS CloudWatch Logs via LocalStack) | Completed |
| **Task 3** | Query for Security-Relevant Activity (Threat Hunting with grep/awk) | Completed |
| **Task 4** | Tamper-Proof (Hash-Chained) Logs using SHA-256 | Completed |
| **Task 5** | Detect the Incident via Multi-Event Correlation (SIEM logic) | Completed |
| **Task 6** | Incident Response: Containment (iptables) & Evidence Preservation (sha256sum) | Completed |
