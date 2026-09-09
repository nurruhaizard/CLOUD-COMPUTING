# CLOUD-COMPUTING: IKB42603 Cloud Computing Security Essentials

**Universiti Kuala Lumpur (UniKL MIIT)**  
**Student Name:** IWANI IZZATI  
**Course Code:** IKB42603 Cloud Computing Security Essentials  
**Program:** Bachelor of Information Technology / Computer Science (Information Security / Cloud Computing)  
**Lecturer:** Prof. Dr. Shahrulniza Musa  

---

## Laboratory Assignments Directory

| Lab Module | Title | Primary Security Domains | Report Link | Evidence Directory |
| :--- | :--- | :--- | :---: | :---: |
| **Lab 2** | Secure Isolation & Multi-Tenancy | Compute, Network, Storage Isolation, NetworkPolicy, RBAC, Data Remanence | [LAB 2 Report](./LAB%202/LAB%202%20IWANI%20IZZATI.md) | [LAB 2 EVIDENCE](./LAB%202/EVIDENCE/) |
| **Lab 5** | Monitoring, Logging & Incident Detection | Telemetry, CloudWatch, Hash-Chained Logs, SIEM Correlation, Incident Response | [LAB 5 Report](./LAB%205/LAB%205%20IWANI%20IZZATI.md) | [LAB 5 Evidence](./LAB%205/Evidence/) |

---

## Lab 2 Overview: Secure Isolation & Multi-Tenancy (Docker & Kubernetes)

- 📘 **Full Report:** [LAB 2 IWANI IZZATI.md](./LAB%202/LAB%202%20IWANI%20IZZATI.md)
- 🖼 **Evidence Repository:** [LAB 2/EVIDENCE/](./LAB%202/EVIDENCE/)
- 📄 **Lab Guide:** [IKB42603_Lab2_Secure_Isolation_and_Multitenancy.pdf](./LAB%202/IKB42603_Lab2_Secure_Isolation_and_Multitenancy.pdf)

### Lab 2 Execution Matrix

| Step / Task | Description | Dimension | Status |
| :--- | :--- | :---: | :---: |
| **Setup** | Deploy kind cluster with `disableDefaultCNI: true` & Project Calico CNI | Network / Compute | Completed |
| **Task 1** | Two Tenants on One Cluster (`tenant-a` & `tenant-b` namespaces, Nginx services) | Compute | Completed |
| **Task 2** | Observe Default-Open Risk (Cross-tenant HTTP probe, HTTP 200 response) | Network | Completed |
| **Task 3** | Contain the Noisy Neighbour (Apply `ResourceQuota` for CPU, memory, and pods) | Compute | Completed |
| **Task 4** | Default-Deny Network Isolation (`default-deny-ingress` NetworkPolicy & verification) | Network | Completed |
| **Task 5** | Storage & Secret Isolation (Per-tenant Secrets & RBAC ServiceAccount verification) | Storage / Identity | Completed |
| **Task 6** | Data Remanence & Secure Deletion (`rm` remanence scan vs. `dd` secure zeroing) | Storage | Completed |

---

## Lab 5 Overview: Monitoring, Logging & Incident Detection

- 📘 **Full Report:** [LAB 5 IWANI IZZATI.md](./LAB%205/LAB%205%20IWANI%20IZZATI.md)
- 🖼 **Evidence Repository:** [LAB 5/Evidence/](./LAB%205/Evidence/)

### Lab 5 Execution Matrix

| Task | Description | Status |
| :--- | :--- | :---: |
| **Task 1** | Generate Application Logs (`auth.log`) | Completed |
| **Task 2** | Centralise Logs (Ship to AWS CloudWatch Logs via LocalStack) | Completed |
| **Task 3** | Query for Security-Relevant Activity (Threat Hunting with grep/awk) | Completed |
| **Task 4** | Tamper-Proof (Hash-Chained) Logs using SHA-256 | Completed |
| **Task 5** | Detect the Incident via Multi-Event Correlation (SIEM logic) | Completed |
| **Task 6** | Incident Response: Containment (`iptables`) & Evidence Preservation (`sha256sum`) | Completed |
