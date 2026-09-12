# UNIVERSITI KUALA LUMPUR (UniKL MIIT)
## IKB42603 Cloud Computing Security Essentials
### Lab Report 6: Object Storage Security & the Data Security Lifecycle
**Bucket Exposure, Resource Policies, SSE-KMS, Versioning and Provable Deletion — Amazon S3 on LocalStack**

---

| Student Information | Academic Details |
| :--- | :--- |
| **Student Name** | NUR IWANI IZZATI BINTI RUHAIZARD |
| **Student ID** | 52215225392D |
| **Course Code** | IKB42603 Cloud Computing Security Essentials |
| **Program** | Bachelor of Information Technology / Computer Science (Information Security / Cloud Computing) |
| **Course Instructor / Lecturer** | Ms Adani *(Course Manual by Prof. Dr. Shahrulniza Musa)* |
| **Lab Module** | Lab 6 (Weeks 11–12): Object Storage Security & Data Lifecycle |
| **GitHub Repository** | [nurruhaizard/CLOUD-COMPUTING](https://github.com/nurruhaizard/CLOUD-COMPUTING) |
| **Academic Term / Submission Date** | September 2026 |

---

## Executive Summary

Object storage services such as Amazon Simple Storage Service (S3) constitute the primary repository for unstructured corporate data, multi-tenant databases, analytical data lakes, and mission-critical backups in modern cloud architectures. However, historical vulnerability data and threat telemetry establish that object storage misconfigurations represent the single most prevalent root cause of catastrophic enterprise cloud data breaches. The fundamental divergence in access control models—shifting from traditional POSIX file systems and block storage primitives to flat-namespace, HTTP-addressable RESTful APIs—frequently leads engineers to commit critical authorization errors.

This laboratory investigation performs an exhaustive, hands-on security assessment of cloud object storage using **Amazon S3 emulation on LocalStack Pro**, governed through the **AWS Command Line Interface (AWS CLI v2)** and evaluated under security frameworks defined by **NIST SP 800-88 Rev. 1**, **NIST SP 800-207 (Zero Trust Architecture)**, **ISO/IEC 27017**, and the **Cloud Security Alliance (CSA) CCSK v5**.

The laboratory work is systematically divided across two interconnected operational phases representing the complete **Data Security Lifecycle**:
1. **Session A (Week 11) — The Exposure Problem & Access Boundary Controls (Tasks 1–4):**
   - Establishing systematic **Data Classification** and object-level metadata tagging (`public`, `internal`, `confidential`).
   - Reproducing the archetypal enterprise breach: exposing sensitive patient records through a wildcard resource policy (`"Principal": "*"`).
   - Enforcing preventative security guardrails via **Amazon S3 Block Public Access (BPA)** across all four structural flags.
   - Implementing Least-Privilege bucket policies and resolving authorization conflicts between **IAM Identity-Based Policies** and **S3 Resource-Based Policies** using the deterministic Cloud Authorization Evaluation Engine (*Default Deny $\rightarrow$ Explicit Deny $\rightarrow$ Explicit Allow*).
2. **Session B (Week 12) — Protecting, Retaining, and Retiring Data (Tasks 5–8):**
   - Enforcing transparent **Server-Side Encryption with AWS KMS (SSE-KMS)** at bucket scale and implementing **S3 Bucket Keys** for envelope encryption optimization.
   - Delegating time-bounded, cryptographically signed access using **Presigned URLs** while analyzing the operational pitfalls of condition-key traps (`aws:SecureTransport`).
   - Investigating **Object-Level Data Remanence** caused by Amazon S3 Versioning and soft delete markers under privacy mandates (GDPR / PDPA).
   - Enforcing automated governance through **S3 Lifecycle Management** and achieving mathematically provable data destruction through **Cryptographic Erasure (Crypto-Shredding)**.

---

## Lab Learning Outcomes & Academic Curriculum Mapping

This laboratory report directly supports and satisfies the designated institutional and international cloud security standards:

| Academic / Professional Item | Specification & Mapping |
| :--- | :--- |
| **Course Learning Outcome (CLO)** | **CLO2:** Construct secure cloud operations that safeguard data confidentiality and integrity (**VBE3**). |
| **Lecture Topics & Alignment** | **Week 4:** Data Protection & Cryptographic Lifecycles.<br>**Week 10:** Cloud Security Policy, Compliance & Risk Management.<br>**Week 11:** Compliance Assessment, Audit Evidence Gathering & Reporting. |
| **Core Values & Skill Clusters** | **VBE3 (Integrity):** Rigorous adherence to forensic data preservation, cryptographic sanitization, and audit verifiability.<br>**SC8 (Integrated Problem-Solving):** Diagnosing cross-cutting authorization logic, mitigating policy lockouts, and designing automated lifecycle retention. |
| **CSA CCSK v5 Domains** | **Domain 5:** Data Security (Classification, Storage Protection, Lifecycle Management).<br>**Domain 4:** Organisation Management & Governance.<br>**Domain 9:** Application Security (Resource-Based Authorization & RESTful APIs). |
| **Regulatory Frameworks** | **PDPA 2010 (Malaysia):** Security Principle & Retention Principle.<br>**GDPR (EU 2016/679):** Article 17 (Right to Erasure / "To Be Forgotten") & Article 32 (Security of Processing).<br>**MCMC MTSFB TC G017:2021:** Cloud Service Provider Information Security Technical Code. |

---

## Theoretical Foundations & Security Architecture

### 1. The Object Storage Paradigm vs. Traditional Storage Primitives

Traditional storage architectures rely on hierarchical POSIX file systems or raw block volumes mounted directly to kernel operating systems. In contrast, cloud object storage is a distributed key-value store accessible exclusively via HTTP/HTTPS RESTful web interfaces:

```
+-----------------------------------------------------------------------------------------------+
|                                      AMAZON S3 KEY SPACE                                      |
|                                                                                               |
|   Bucket Name: miit-patient-records-3104                                                      |
|   +---------------------------------------+-----------------------------------------------+   |
|   | Object Key (String Identifier)        | Byte Payload & Metadata                       |   |
|   +---------------------------------------+-----------------------------------------------+   |
|   | public/notice.txt                     | Body: 29 bytes | Tag: classification=public   |   |
|   | internal/roster.txt                   | Body: 29 bytes | Tag: classification=internal |   |
|   | confidential/record.txt               | Body: 48 bytes | Tag: classification=confid.  |   |
|   +---------------------------------------+-----------------------------------------------+   |
+-----------------------------------------------------------------------------------------------+
```

Key architectural distinctions:
- **Flat Namespace:** S3 possesses no native directories or subfolders. The forward slash (`/`) in `confidential/record.txt` is merely a character within an arbitrary UTF-8 key string.
- **Exposure Blast Radius:** Because access control policies evaluate key prefixes (e.g., `confidential/*`), a poorly constructed wildcard such as `arn:aws:s3:::bucket/*` exposes every object stored within the entire repository.
- **Direct Internet Addressability:** Unlike block volumes residing behind private network controllers, every S3 bucket possesses a globally routable DNS endpoint (e.g., `http://localhost:4566/bucket-name` in LocalStack or `https://bucket-name.s3.amazonaws.com` in production).

---

### 2. Cloud Authorization Logic: Identity Policies vs. Resource Policies

When an authenticated identity attempts to interact with an Amazon S3 object, the AWS Access Evaluation Engine cross-evaluates both **Identity-Based Policies** (attached to the IAM user or role) and **Resource-Based Policies** (the S3 Bucket Policy).

```mermaid
flowchart TD
    Start([Incoming Request to S3]) --> Eval1{Explicit Deny in ANY Policy?}
    Eval1 -- Yes --> DenyAction[Final Decision: REJECTED / ACCESS DENIED]
    Eval1 -- No --> Eval2{Explicit Allow in EITHER Policy?}
    Eval2 -- Yes --> AllowAction[Final Decision: PERMITTED / ACCESS GRANTED]
    Eval2 -- No --> DefaultDeny[Final Decision: IMPLICIT DENY / BLOCKED]

    style DenyAction fill:#ff4d4d,stroke:#333,stroke-width:2px,color:#fff
    style AllowAction fill:#2eb82e,stroke:#333,stroke-width:2px,color:#fff
    style DefaultDeny fill:#ffa31a,stroke:#333,stroke-width:2px,color:#fff
```

Deterministic evaluation rules:
1. **Default Deny:** By default, all requests are implicitly denied.
2. **Explicit Deny Precedence:** If *any* policy (identity or resource) contains an explicit `"Effect": "Deny"`, that statement instantaneously overrides all existing allows, unconditionally terminating authorization.
3. **Union of Allows (Same Account):** Within the same AWS account, an explicit `"Effect": "Allow"` in *either* the identity policy *or* the resource policy is sufficient to grant access, provided no explicit Deny exists.

---

### 3. S3 Versioning, Delete Markers, and Data Remanence

When Amazon S3 Versioning is enabled on a bucket, standard deletion operations do not purge the underlying storage blocks. Instead, S3 inserts an empty metadata record known as a **Delete Marker** with its own unique `VersionId`.

```mermaid
sequenceDiagram
    autonumber
    actor Client as Data Subject / User
    participant S3 as Amazon S3 Bucket API
    participant Store as Physical / Virtual Storage Pool

    Note over S3,Store: Object State: [Version v1 (null)], [Version v2], [Version v3]
    Client->>S3: DELETE /confidential/record.txt (Standard API call)
    S3->>Store: Insert Delete Marker (IsLatest = True)
    S3-->>Client: HTTP 204 No Content (Object marked deleted)
    
    Client->>S3: GET /confidential/record.txt
    S3-->>Client: HTTP 404 NoSuchKey (Appears deleted to standard clients)
    
    Client->>S3: GET /confidential/record.txt?versionId=null
    S3->>Store: Retrieve Byte Stream of Version 'null'
    S3-->>Client: HTTP 200 OK + Unredacted Confidential Payload! (Data Remanence)
    
    Client->>S3: DELETE /confidential/record.txt?versionId=null (Permanent Purge)
    S3->>Store: Purge Version 'null' Metadata & Payload
    S3-->>Client: HTTP 204 Deleted
```

This operational mechanism creates substantial compliance liability under privacy frameworks such as **GDPR Article 17** and the **Malaysian Personal Data Protection Act (PDPA) 2010**. Unless an organization explicitly executes targeted per-version permanent deletions or automated lifecycle expirations, sensitive data remains retrievable in perpetuity.

---

### 4. Cryptographic Erasure (Crypto-Shredding)

Traditional data destruction standards (such as DoD 5220.22-M or NIST SP 800-88 physical degaussing and overwriting) are impossible for cloud tenants because tenants have no physical or low-level hypervisor access to storage drives. **Cryptographic Erasure** solves this architectural challenge:

```mermaid
flowchart LR
    subgraph StoragePool["Multi-Tenant Physical Storage"]
        Ciphertext["Encrypted Object Payload (AES-256-GCM)"]
    end

    subgraph KMS["AWS Key Management Service (KMS)"]
        CMK["Customer Master Key (CMK)<br/>KeyId: 8eceab89..."]
    end

    CMK -.->|Decrypt Data Key| Ciphertext
    Admin([Security Administrator]) -->|kms schedule-key-deletion| KMS
    KMS -->|Key Destroyed / State: PendingDeletion| NullKey["Key Material Destroyed"]
    NullKey -.->|Decryption Impossible| Ciphertext
    Ciphertext --> RandomNoise["Mathematically Indistinguishable from Random Noise"]

    style NullKey fill:#ff3333,stroke:#333,stroke-width:2px,color:#fff
    style RandomNoise fill:#3399ff,stroke:#333,stroke-width:2px,color:#fff
```

By destroying or irrevocably disabling the KMS Customer Master Key (CMK) that encrypts the bucket objects, the remaining ciphertext becomes computationally unrecoverable. Even if threat actors extract the physical drives from the cloud datacenter or unearth historical snapshots, the data cannot be decrypted within human civilization lifetimes.

---

## Technical Prerequisites & Emulated Environment Setup

The hands-on laboratory exercises were conducted inside a dedicated penetration testing and security assessment workstation (**Kali Linux x86_64**) using the official AWS CLI v2 and LocalStack Pro container engine:

```bash
# Clean up any stale container instance
docker rm -f localstack 2>/dev/null

# Launch LocalStack Pro with explicit IAM policy enforcement enabled
docker run -d --name localstack -p 4566:4566 \
  -e LOCALSTACK_AUTH_TOKEN=$LOCALSTACK_AUTH_TOKEN \
  -e ENFORCE_IAM=1 \
  localstack/localstack-pro:latest

# Configure global environment variables pointing CLI to LocalStack
export EP='--endpoint-url=http://localhost:4566'
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

# Validate cloud caller identity
aws $EP sts get-caller-identity
```

Output:
```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

The returned identity confirms operating as the simulated root administrator under Account ID `000000000000`.

---

## Session A (Week 11) — Object Storage & The Exposure Problem

### Task 1 — Classify the Data Before You Store It

Security engineering dictates that access controls must be derived directly from formal **Data Classification** rather than applied ad-hoc. A unique S3 bucket was provisioned for an enterprise hospital patient records management system:

```bash
export BUCKET=miit-patient-records-$RANDOM
echo $BUCKET
```
Bucket identifier generated: **`miit-patient-records-3104`**.

```bash
aws $EP s3api create-bucket --bucket $BUCKET
```

Three discrete data payloads representing distinct classification tiers were generated and stored with explicit object tagging:
1. **Public Tier (`public/notice.txt`):** General hospital operational details (`Ward visiting hours 10am-8pm`). Tagged `classification=public`.
2. **Internal Tier (`internal/roster.txt`):** Departmental staffing schedules (`Staff duty schedule, week 12`). Tagged `classification=internal`.
3. **Confidential Tier (`confidential/record.txt`):** Highly restricted Protected Health Information (PHI) (`Patient: Ahmad bin Ali, Diagnosis: confidential`). Tagged `classification=confidential`.

```bash
# Create local data files
echo 'Ward visiting hours 10am-8pm' > public-notice.txt
echo 'Staff duty schedule, week 12' > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential' > confidential-record.txt

# Ingest into object storage with classification metadata tags
aws $EP s3api put-object --bucket $BUCKET --key public/notice.txt \
  --body public-notice.txt --tagging 'classification=public'

aws $EP s3api put-object --bucket $BUCKET --key internal/roster.txt \
  --body internal-roster.txt --tagging 'classification=internal'

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body confidential-record.txt --tagging 'classification=confidential'

# Audit bucket contents and tag assignments
aws $EP s3api list-objects-v2 --bucket $BUCKET --query 'Contents[].[Key,Size]' --output table
aws $EP s3api get-object-tagging --bucket $BUCKET --key confidential/record.txt
```

#### Task 1 Evidence:
![Task 1 Classification and Storage Evidence](./Evidence/Task%201%20—%20Classify%20the%20Data%20Before%20You%20Store%20It%20(1).png)

![Task 1 Object Listing Table and TagSet](./Evidence/Task%201%20—%20Classify%20the%20Data%20Before%20You%20Store%20It%20(2).png)

The resulting object index confirms the exact payload byte sizes:
- `confidential/record.txt`: **48 bytes**
- `internal/roster.txt`: **29 bytes**
- `public/notice.txt`: **29 bytes**

The `get-object-tagging` inspection confirms the object carries the formal metadata key-value pair:
```json
{
    "TagSet": [
        {
            "Key": "classification",
            "Value": "confidential"
        }
    ]
}
```

---

### Task 2 — Reproduce the Archetypal Cloud Breach

In real-world cloud security post-mortems (e.g., Capital One, Accenture, Booz Allen Hamilton), data breaches rarely stem from zero-day kernel exploits. Instead, they occur when administrators misconfigure resource policies to grant anonymous global access.

To reproduce this vulnerability, a wide-open bucket resource policy was deliberately authored and attached:

```bash
cat > public-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicReadEverything",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET/*"
  }]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text
```

#### Simulating the Anonymous External Adversary
An external attacker possessing no AWS IAM credentials, no secret keys, and no CLI environment simply fires an unauthenticated HTTP GET request over the public internet to the bucket's URI:

```bash
curl -s -o leaked.txt -w 'HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
cat leaked.txt
```

#### Task 2 Evidence:
![Task 2 Public Bucket Breach Reproduction](./Evidence/Task%202%20—%20Reproduce%20the%20Archetypal%20Breach.png)

#### Forensic Observation:
The terminal verifies an immediate **`HTTP 200 OK`** response. Displaying `leaked.txt` reveals:
```
HTTP 200
Patient: Ahmad bin Ali, Diagnosis: confidential
```
**Root Cause Analysis:** The catastrophic exposure was caused entirely by the single JSON element:
```json
"Principal": "*"
```
Combined with the resource ARN `arn:aws:s3:::miit-patient-records-3104/*`, this statement completely bypassed authentication, instructing the S3 API gateway to serve confidential hospital records to any unauthenticated client on Earth.

---

### Task 3 — Remediate with Block Public Access (BPA)

Remediating a cloud breach requires a two-layer defense: deleting the insecure policy (immediate tactical fix) and establishing an immutable governance guardrail (strategic preventative control). **Amazon S3 Block Public Access (BPA)** operates as a centralized account-level and bucket-level circuit breaker that overrides all current and future bucket policies and ACLs.

```bash
# Step 1: Remove the compromised public policy
aws $EP s3api delete-bucket-policy --bucket $BUCKET

# Step 2: Apply the four-point Block Public Access preventative guardrail
aws $EP s3api put-public-access-block --bucket $BUCKET \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Step 3: Verify the active guardrail posture
aws $EP s3api get-public-access-block --bucket $BUCKET
```

#### The Four Pillars of S3 Block Public Access:
1. **`BlockPublicAcls`:** Prohibits the upload of new objects with public access control lists.
2. **`IgnorePublicAcls`:** Causes S3 to ignore all existing public ACLs on objects within the bucket.
3. **`BlockPublicPolicy`:** Rejects any `put-bucket-policy` request that would grant public access.
4. **`RestrictPublicBuckets`:** Restricts access to buckets with public policies to AWS services and authorized users within the bucket owner's account.

```bash
# Step 4: Re-attempt applying the public policy (Guardrail testing)
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json

# Step 5: Probe anonymous endpoint
curl -s -o /dev/null -w 'anonymous read now: HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
```

#### Task 3 Evidence:
![Task 3 Block Public Access Guardrail](./Evidence/Task%203%20—%20Remediate%20with%20Block%20Public%20Access.png)

![Task 3 Least-Privilege Bucket Policy](./Evidence/Task%203%20—%20Remediate%20with%20Block%20Public%20Access%20(2).png)

#### Architectural Verification & Emulation Analysis:
Inspection of `get-public-access-block` confirms all four boolean flags are active (`true`). 
> **Evaluation Note:** In real AWS production, Step 4 would be immediately terminated by the S3 control plane with `AccessDenied: Bucket cannot have public policy when BlockPublicPolicy is set`. In LocalStack's lightweight emulator, the BPA metadata state is persisted faithfully, but policy rejection triggers are bypassed on simulated endpoints. 
> 
> A **preventative guardrail** is fundamentally superior to a **detective control**: detective controls (such as AWS Config rules or SIEM alerts) only notify security teams *after* data has already been leaked to the internet. A preventative guardrail halts the dangerous API transaction at the control plane, rendering accidental exposure mathematically impossible.

#### Enforcing Least-Privilege Scoping:
The bucket policy was replaced with a correctly scoped, least-privilege resource policy granting read access strictly to authenticated identities within Account `000000000000` and restricted solely to the `internal/*` prefix:

```bash
cat > least-privilege-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AccountReadInternalOnly",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET/internal/*"
  }]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://least-privilege-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text
```

---

### Task 4 — Identity Policy vs. Resource Policy Conflict Resolution

In enterprise environments, data analysts and business intelligence tools are often assigned broad permissions to perform bulk data ingestion. Security engineers must ensure that bucket-level resource policies effectively enforce data boundaries when identity policies are overly permissive.

#### 1. Provisioning User `DataAnalyst` with Broad Identity Permissions:
```bash
aws $EP iam create-user --user-name DataAnalyst

cat > analyst-iam.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": "*"
  }]
}
JSON

aws $EP iam put-user-policy --user-name DataAnalyst \
  --policy-name S3ReadAll --policy-document file://analyst-iam.json

aws $EP iam create-access-key --user-name DataAnalyst \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text
```

Generated Credentials:
- Access Key ID: `LKIAQAAAAAAAIX7OTNIP`
- Secret Access Key: `VCDUu1s37tvR9yCNpu8LcwFkY9QkrPy76OEiF2J0`

A dedicated AWS CLI profile `analyst` was configured:
```bash
aws configure --profile analyst set aws_access_key_id "LKIAQAAAAAAAIX7OTNIP"
aws configure --profile analyst set aws_secret_access_key "VCDUu1s37tvR9yCNpu8LcwFkY9QkrPy76OEiF2J0"
aws configure --profile analyst set region us-east-1
```

#### Task 4 Evidence (User Creation & Credential Setup):
![Task 4 Analyst User Creation and IAM Setup](./Evidence/Task%204%20—%20Identity%20Policy%20vs%20Resource%20Policy%20(1).png)

#### 2. Defining Conflicting Bucket Resource Policy:
The bucket owner establishes a resource policy with two contradictory directives regarding user `DataAnalyst`:
1. **Allow Statement (`AllowAnalystInternal`):** Explicitly allows `s3:GetObject` on `internal/*`.
2. **Deny Statement (`DenyAnalystConfidential`):** Explicitly denies `s3:*` on `confidential/*`.

```bash
cat > deny-confidential.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAnalystInternal",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$BUCKET/internal/*"
    },
    {
      "Sid": "DenyAnalystConfidential",
      "Effect": "Deny",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::$BUCKET/confidential/*"
    }
  ]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://deny-confidential.json
aws $EP s3api get-bucket-policy --bucket $BUCKET
```

#### Task 4 Evidence (Resource Policy JSON Definition):
![Task 4 Deny Confidential Policy Definition](./Evidence/Task%204%20—%20Identity%20Policy%20vs%20Resource%20Policy%20(2).png)

#### 3. Empirical Evaluation of Conflicting Policies:
The analyst attempts two sequential read operations:

```bash
# Attempt 1: Read Internal Roster (Both policies agree)
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key internal/roster.txt analyst-internal.txt && echo "internal: ALLOWED"

# Attempt 2: Read Confidential Patient Record (Policies conflict)
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key confidential/record.txt analyst-conf.txt || echo "confidential: DENIED"
```

#### Task 4 Evidence (Evaluation Results):
![Task 4 Internal Allowed Execution](./Evidence/Task%204%20—%20Identity%20Policy%20vs%20Resource%20Policy%20(3).png)

![Task 4 Confidential Evaluation Execution](./Evidence/Task%204%20—%20Identity%20Policy%20vs%20Resource%20Policy%20(4).png)

#### Theoretical Evaluation Breakdown:
- **Request 1 (`internal/roster.txt`):** The identity policy permits reading all S3 objects (`Resource: *`). The bucket policy explicitly permits reading `internal/*`. Because both policies allow the operation and neither denies it, the authorization engine evaluates to **`internal: ALLOWED`** (HTTP 200).
- **Request 2 (`confidential/record.txt`):** The identity policy permits reading the object (`Resource: *`). However, the bucket resource policy contains statement `DenyAnalystConfidential` (`Effect: Deny`). Under the AWS Evaluation Engine, an **Explicit Deny unconditionally overrides any Allow**. On production AWS, this request is immediately rejected with an `AccessDenied (HTTP 403)` error.

---

## Session B (Week 12) — Protecting, Retaining and Retiring Data

### Task 5 — Default Encryption at Rest (SSE-KMS)

Relying on developers to remember encryption parameters during upload is a major operational vulnerability. Enterprise cloud security requires establishing **Default Bucket Encryption**, ensuring every byte ingested into the bucket is automatically encrypted using an AWS Key Management Service (KMS) Customer Master Key (CMK).

#### 1. Provisioning Dedicated KMS Customer Master Key:
```bash
export KEY_ID=$(aws $EP kms create-key \
  --description 'IKB42603 Lab6 patient records bucket key' \
  --query 'KeyMetadata.KeyId' --output text)
echo $KEY_ID
```
Generated KMS Key ID: **`8eceab89-3cc3-4335-a99b-72898a1c6fcc`**.

#### 2. Enforcing SSE-KMS & S3 Bucket Key Optimization:
```bash
cat > encryption.json <<JSON
{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "$KEY_ID"
    },
    "BucketKeyEnabled": true
  }]
}
JSON

aws $EP s3api put-bucket-encryption --bucket $BUCKET \
  --server-side-encryption-configuration file://encryption.json

aws $EP s3api get-bucket-encryption --bucket $BUCKET
```

#### Task 5 Evidence (KMS Key Creation & Bucket Configuration):
![Task 5 Default Encryption Configuration](./Evidence/Task%205%20—%20Default%20Encryption%20at%20Rest%20(SSE-KMS).png)

#### 3. Ingestion Without Encryption Parameters:
A new confidential record (`confidential/record-v2.txt`) was uploaded without specifying any server-side encryption flags. The object's metadata headers were then probed using `head-object`:

```bash
aws $EP s3api put-object --bucket $BUCKET \
  --key confidential/record-v2.txt --body confidential-record.txt

aws $EP s3api head-object --bucket $BUCKET --key confidential/record-v2.txt \
  --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' --output text
```

#### Task 5 Evidence (Head-Object Verification):
![Task 5 Ingestion and Head-Object Verification](./Evidence/Task%205%20—%20Default%20Encryption%20at%20Rest%20(SSE-KMS)%20(2).png)

#### Verification Output:
```
aws:kms   arn:aws:kms:us-east-1:000000000000:key/8eceab89-3cc3-4335-a99b-72898a1c6fcc   True
```
This confirms that the default bucket policy automatically intercepted the plaintext stream and encrypted it under our customer-managed key. 

> **Security & Cost Benefit of S3 Bucket Keys (`BucketKeyEnabled: true`):**
> Standard SSE-KMS generates an individual `kms:GenerateDataKey` and `kms:Decrypt` API call for every single S3 PUT and GET transaction. In high-throughput environments, this causes KMS API throttling and significant billing costs ($0.03 per 10,000 requests). Enabling **S3 Bucket Keys** creates a time-bounded bucket-level data key cache. S3 reuses this intermediate key to encrypt hundreds of individual objects locally using envelope encryption, cutting KMS API requests by up to **99%** while maintaining identical cryptographic confidentiality.

---

### Task 6 — Delegated Access and the Condition-Key Trap

Cloud architectures often require sharing objects with external entities (e.g., third-party auditors or medical specialists) who lack AWS credentials. **Presigned URLs** embed cryptographic proof of authorization directly into HTTP query parameters.

#### 1. Generating & Exercising a Time-Bounded Presigned URL:
```bash
# Generate a 60-second presigned URL for internal roster
aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60
```

Generated URL:
```
http://localhost:4566/miit-patient-records-3104/internal/roster.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test%2F20260912%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260912T102833Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=51184415c541967440f9609c21d1f2125d4c66fc007a67f45d4c4dba3ea6c14f
```

The URL was stored in an environment variable and accessed anonymously:
```bash
URL='http://localhost:4566/miit-patient-records-3104/internal/roster.txt?...'
curl -s -w ' <-- HTTP %{http_code}\n' "$URL"

# Sleep past the expiration threshold and re-test
sleep 65
curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"
```

#### Cryptographic Mechanics of Presigned URLs:
- **`X-Amz-Algorithm=AWS4-HMAC-SHA256`:** Declares the cryptographic hashing algorithm used to compute the signature.
- **`X-Amz-Credential`:** Binds the identity of the signer and the request date scope.
- **`X-Amz-Expires=60`:** Defines the lifespan in seconds from `X-Amz-Date`.
- **`X-Amz-Signature`:** An HMAC-SHA256 hash computed using the signer's Secret Access Key over the canonical request string (HTTP verb, URI, query string, host header). Any tampering with the query parameters invalidates the hash.

#### 2. The Condition-Key Trap (`aws:SecureTransport`):
Security compliance checklists universally mandate that all storage traffic be encrypted in transit via TLS. The industry-standard policy snippet is:

```bash
cat > secure-transport.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::$BUCKET", "arn:aws:s3:::$BUCKET/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://secure-transport.json
```

#### Task 6 Evidence (Presigned URL & Secure Transport Policy):
![Task 6 Presigned URL Generation and Transport Policy](./Evidence/Task%206%20—%20Delegated%20Access%20and%20the%20Condition-Key%20Trap.png)

#### Observing the Condition-Key Trap:
When executing any administrative operation:
```bash
aws $EP s3api list-objects-v2 --bucket $BUCKET
```

#### Task 6 Evidence (List Objects Execution & Policy Recovery):
![Task 6 List Objects Under Policy](./Evidence/Task%206%20—%20Delegated%20Access%20and%20the%20Condition-Key%20Trap%20(2).png)

![Task 6 Deleting Transport Policy](./Evidence/Task%206%20—%20Delegated%20Access%20and%20the%20Condition-Key%20Trap%20(3).png)

```bash
# Emergency recovery: Remove policy to restore operations
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

#### Root Cause Analysis:
The policy itself is syntactically flawless and complies with AWS Security Hub standards. However, in our LocalStack environment, the endpoint is configured as plain HTTP (`http://localhost:4566`). Because the transport is not TLS, `aws:SecureTransport` evaluates to `false` for **every single incoming API call**. 

Consequently, the condition matches the explicit Deny rule, instantly locking out the entire engineering team, including administrators. 

> **Lesson:** Security condition keys must always be validated against the specific target runtime environment (protocol, networking boundaries, proxies) rather than blindly copied from hardening guides.

---

### Task 7 — Versioning, Delete Markers & Object Data Remanence

When organizations enable S3 Versioning to defend against accidental deletion or ransomware, they inadvertently introduce **Data Remanence risks**. Deleting an object merely inserts a Delete Marker. The prior versions containing confidential information remain fully accessible to anyone querying the version index.

#### 1. Enabling Versioning and Ingesting Record Revisions:
```bash
aws $EP s3api put-bucket-versioning --bucket $BUCKET \
  --versioning-configuration Status=Enabled

aws $EP s3api get-bucket-versioning --bucket $BUCKET

# Generate subsequent revisions simulating diagnosis changes and redaction
echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]' > rec-v3.txt

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v2.txt --query VersionId --output text

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v3.txt --query VersionId --output text

aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,IsLatest,Size]' --output table
```

#### Task 7 Evidence (Versioning and Multiple Revisions):
![Task 7 Versioning Enabled and Object Revision Index](./Evidence/Task%207%20—%20Versioning,%20Delete%20Markers%20&%20Data%20Remanence%20(1).png)

Version Table Inspection:
- `AaCAl9L56f8LXxj2g.GCjgtnuwKGwDZz`: IsLatest = **True** (Revision v3, Redacted, 43 bytes)
- `AaCAl9L4dmB1vS30EHiGshm5SMTUb5eK`: IsLatest = **False** (Revision v2, Hypertension, 48 bytes)
- `null`: IsLatest = **False** (Revision v1, Original Diagnosis, 48 bytes — uploaded in Task 1 before versioning was activated)

#### 2. The Illusion of Deletion (Delete Markers & Remanence):
An administrator "deletes" the confidential record:

```bash
aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt

# Inspect delete markers
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'DeleteMarkers[].[VersionId,IsLatest]' --output table

# Standard GET request returns NoSuchKey
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt /dev/null

# Forensic recovery of the supposedly deleted data
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt \
  --version-id null recovered.txt
cat recovered.txt
```

#### Task 7 Evidence (Delete Marker Creation and Forensic Recovery):
![Task 7 Delete Marker and Unredacted Recovery](./Evidence/Task%207%20—%20Versioning,%20Delete%20Markers%20&%20Data%20Remanence%20(2).png)

#### Forensic Finding:
The standard `get-object` command returned:
```
aws: [ERROR]: An error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist.
```
However, invoking `--version-id null` retrieved the original file. Output of `recovered.txt`:
```
Patient: Ahmad bin Ali, Diagnosis: confidential
```
The original PHI diagnosis, redacted in v3 and supposedly "deleted", was fully recovered. In the context of **GDPR Article 17** or **PDPA 2010**, relying on standard deletion in a versioned bucket constitutes a severe compliance violation.

#### 3. Permanent, Per-Version Purge:
To achieve true data sanitization, each underlying version must be purged by specifying its exact `VersionId`:

```bash
aws $EP s3api delete-object --bucket $BUCKET \
  --key confidential/record.txt --version-id null

aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt
```

#### Task 7 Evidence (Targeted Per-Version Deletion & Audit):
![Task 7 Per-Version Permanent Deletion](./Evidence/Task%207%20—%20Versioning,%20Delete%20Markers%20&%20Data%20Remanence%20(3).png)

![Task 7 Version Audit Post-Purge](./Evidence/Task%207%20—%20Versioning,%20Delete%20Markers%20&%20Data%20Remanence%20(4).png)

The version listing confirms that Version `null` has been permanently expunged from the storage pool.

---

### Task 8 — Lifecycle, Retention & Cryptographic Erasure

In enterprise cloud infrastructures hosting petabytes of data, manual per-version deletion does not scale. Compliance requires two complementary automated controls:
1. **S3 Lifecycle Management Policies** for programmatic, automated data retention and noncurrent version expiration.
2. **KMS Cryptographic Erasure** for instantaneous, provable sanitization across all distributed replicas.

#### 1. Enforcing Automated Lifecycle Retention Rules:
```bash
cat > lifecycle.json <<'JSON'
{
  "Rules": [
    {
      "ID": "RetireConfidentialRecords",
      "Filter": {"Prefix": "confidential/"},
      "Status": "Enabled",
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    },
    {
      "ID": "AbortIncompleteUploads",
      "Filter": {"Prefix": ""},
      "Status": "Enabled",
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
    }
  ]
}
JSON

aws $EP s3api put-bucket-lifecycle-configuration --bucket $BUCKET \
  --lifecycle-configuration file://lifecycle.json

aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID, Status, Filter.Prefix, Expiration.Days, NoncurrentVersionExpiration.NoncurrentDays]' \
  --output table
```

#### Task 8 Evidence (Lifecycle Rule Application):
![Task 8 Lifecycle Rule Verification](./Evidence/Task%208%20–%20Lifecycle.png)

Verification Table:
- Rule `RetireConfidentialRecords`: Applied to prefix `confidential/`, expires active objects at **365 days**, and purges noncurrent versions at **30 days**.
- Rule `AbortIncompleteUploads`: Purges orphaned multipart upload chunks after **7 days**, preventing hidden storage consumption.

#### 2. Provable Deletion via KMS Cryptographic Erasure:
To retire the bucket's confidential records instantaneously across all backups, snapshots, and versioned copies, the backing KMS key is destroyed:

```bash
# Verify current key state
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.KeyState' --output text

# Schedule irrevocable key deletion
aws $EP kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7

# Verify key state transition
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyState,DeletionDate]' --output text

# Attempt reading object encrypted under the disabled/erased key
aws $EP s3api get-object --bucket $BUCKET \
  --key confidential/record-v2.txt after-erasure.txt
```

#### Task 8 Evidence (KMS Cryptographic Erasure):
![Task 8 KMS Cryptographic Erasure Execution](./Evidence/Task%208%20–%20Cryptographic%20Erasure.png)

The key state shifted from **`Enabled`** to **`PendingDeletion`** (scheduled for destruction on `2026-09-15T18:53:27+08:00`). 

> **Auditor Assurance of Cryptographic Erasure vs. Traditional Overwriting:**
> In a shared, multi-tenant cloud environment, tenants do not control the physical flash memory or hard disk drives. Cloud storage layers implement **Wear-Leveling**, **Copy-on-Write**, and distributed striping across availability zones, meaning traditional software overwrite tools (`shred`, `dd if=/dev/zero`) cannot guarantee that physical blocks were zeroed. 
> 
> In contrast, **Cryptographic Erasure (NIST SP 800-88 Rev. 1 Section 2.5)** targets the cryptographic root of trust. Because every block of ciphertext was encrypted using AES-256-GCM, destroying the master key renders the data mathematically impossible to decrypt. This provides auditors with incontrovertible mathematical proof of data destruction across all distributed replicas without requiring access to physical hardware.

---

## Deliverables & Academic Assessment Questions

### Deliverable 1: Evidence Screenshot Mapping Matrix

All 20 laboratory screenshots have been verified and documented:

| Task / Deliverable | File Name in `Evidence/` | Forensic Content & Security Purpose |
| :--- | :--- | :--- |
| **Task 1.1** | `Task 1 — Classify the Data Before You Store It (1).png` | Creation of bucket `miit-patient-records-3104`, generation of 3 sample files, and upload with classification metadata tags. |
| **Task 1.2** | `Task 1 — Classify the Data Before You Store It (2).png` | Output table of `list-objects-v2` showing keys/sizes, and `get-object-tagging` confirming `classification=confidential`. |
| **Task 2** | `Task 2 — Reproduce the Archetypal Breach.png` | Application of `public-policy.json` (`Principal: "*"`), policy verification, and anonymous curl reading `confidential/record.txt` (HTTP 200). |
| **Task 3.1** | `Task 3 — Remediate with Block Public Access.png` | Policy deletion, application of S3 Block Public Access (all 4 flags true), verification via `get-public-access-block`, and anonymous curl re-test. |
| **Task 3.2** | `Task 3 — Remediate with Block Public Access (2).png` | Creation and enforcement of scoped `least-privilege-policy.json` granting account root access to `internal/*`. |
| **Task 4.1** | `Task 4 — Identity Policy vs Resource Policy (1).png` | Creation of IAM user `DataAnalyst`, attaching `S3ReadAll` identity policy, access key generation, and configuring profile `analyst`. |
| **Task 4.2** | `Task 4 — Identity Policy vs Resource Policy (2).png` | Resource policy `deny-confidential.json` defining `AllowAnalystInternal` and explicit `DenyAnalystConfidential`. |
| **Task 4.3** | `Task 4 — Identity Policy vs Resource Policy (3).png` | Applying resource policy, verification, and testing `get-object` on `internal/roster.txt` under `analyst` profile (`internal: ALLOWED`). |
| **Task 4.4** | `Task 4 — Identity Policy vs Resource Policy (4).png` | Testing `get-object` on `confidential/record.txt` under `analyst` profile, documenting explicit Deny precedence. |
| **Task 5.1** | `Task 5 — Default Encryption at Rest (SSE-KMS).png` | Provisioning KMS CMK `8eceab89-3cc3-4335-a99b-72898a1c6fcc`, applying `encryption.json` (`aws:kms`, `BucketKeyEnabled: true`), and verification. |
| **Task 5.2** | `Task 5 — Default Encryption at Rest (SSE-KMS) (2).png` | Uploading `confidential/record-v2.txt` with no flags, proving automatic encryption via `head-object` (`aws:kms`, KMS key ARN, `BucketKeyEnabled: True`). |
| **Task 6.1** | `Task 6 — Delegated Access and the Condition-Key Trap.png` | Generating 60s presigned URL, anonymous curl verification (HTTP 200), expiration test, and writing `secure-transport.json`. |
| **Task 6.2** | `Task 6 — Delegated Access and the Condition-Key Trap (2).png` | Executing `list-objects-v2` under secure transport policy demonstrating environment evaluation. |
| **Task 6.3** | `Task 6 — Delegated Access and the Condition-Key Trap (3).png` | Removing `secure-transport.json` policy to restore normal bucket accessibility. |
| **Task 7.1** | `Task 7 — Versioning, Delete Markers & Data Remanence (1).png` | Enabling versioning (`Status=Enabled`), uploading v2 (`hypertension`) and v3 (`[REDACTED]`), and inspecting version table. |
| **Task 7.2** | `Task 7 — Versioning, Delete Markers & Data Remanence (2).png` | Deleting object creating Delete Marker `AaCAl9L6Lznt0Pi9CzIl13gPDq48iFc0`, proving standard read returns `NoSuchKey`, and recovering unredacted diagnosis from version `null`. |
| **Task 7.3** | `Task 7 — Versioning, Delete Markers & Data Remanence (3).png` | Targeted per-version permanent deletion via `delete-object --version-id null`. |
| **Task 7.4** | `Task 7 — Versioning, Delete Markers & Data Remanence (4).png` | Querying `list-object-versions` verifying permanent eradication of version `null`. |
| **Task 8.1** | `Task 8 – Lifecycle.png` | Applying `lifecycle.json` (`RetireConfidentialRecords`: 365-day current expiration, 30-day noncurrent version expiration) and table verification. |
| **Task 8.2** | `Task 8 – Cryptographic Erasure.png` | KMS key state inspection (`Enabled`), scheduling deletion (`PendingDeletion`), status verification, and probing encrypted object. |

---

### Deliverable 2: Completed Data Classification Table

The completed four-column data classification table, detailing who may read the data, the security and regulatory impact if breached, and the technical control implemented during the lab:

| Classification | Who may read it | Impact if leaked | Control you will apply |
| :--- | :--- | :--- | :--- |
| **`public`** | Any member of the general public, patients, and external visitors. | **Negligible.** Public visiting hours and general notices carry no confidentiality requirements. Unauthorized modification (integrity loss) could cause operational disruption. | Scoped bucket policy prefix (`public/*`), S3 Block Public Access enabled to prevent unauthorized ACL modifications, and integrity hashing. |
| **`internal`** | Authenticated hospital healthcare staff, attending nurses, and administrative personnel. | **Moderate.** Departmental rosters and duty schedules expose internal staffing levels and shift patterns, creating social engineering and physical security risks. | Authenticated IAM identity access only, prefix-scoped resource policy (`internal/*`), and time-bounded HMAC Presigned URLs for controlled delegation. |
| **`confidential`** | Authorized primary care physicians, attending specialists, and the specific individual patient. | **Severe / Catastrophic.** Unrestricted exposure of Protected Health Information (PHI) and medical diagnoses violates PDPA 2010 / GDPR, resulting in severe regulatory fines, lawsuits, and irrevocable loss of patient trust. | Default Server-Side Encryption with KMS CMK (`SSE-KMS`), S3 Bucket Keys, explicit Deny resource policies, noncurrent version expiration, and Cryptographic Erasure. |

---

### Deliverable 3: In-Depth Short-Answer Questions

#### Question 1:
**Which single element of the Task 2 policy caused the exposure, and why is `Principal: "*"` more dangerous on a bucket policy than an over-broad IAM policy attached to one user?**

- **The Root Cause Element:** The exposure was caused by `"Principal": "*"`.
- **Architectural Danger Analysis:** An over-broad IAM identity policy (e.g., granting `AdministratorAccess` or `s3:*` on `*`) is dangerous, but its blast radius is strictly constrained to the *authenticated boundaries of that specific user identity*. An attacker cannot leverage that policy unless they first acquire valid cryptographic credentials (access key ID and secret access key) belonging to that user.
- In stark contrast, a bucket resource policy that specifies `"Principal": "*"` **eliminates the authentication requirement entirely**. It instructs the AWS S3 API gateway to bypass identity verification and serve objects to completely anonymous, unauthenticated callers over the public internet. Furthermore, because S3 buckets possess globally routable DNS endpoints, anyone with an internet connection can access the data without leaving an IAM credential trail.

---

#### Question 2:
**Explain the difference between an identity-based policy and a resource-based policy. In Task 4, which one decided each of the analyst's two requests?**

- **Identity-Based vs. Resource-Based Policies:**
  - An **Identity-Based Policy** is attached directly to an IAM user, group, or role. It governs what actions that specific identity can execute across various AWS resources (specifying `Action` and `Resource`, but omitting `Principal` because the principal is implicitly the entity to which it is attached).
  - A **Resource-Based Policy** is attached directly to the cloud resource itself (in this case, the S3 bucket). It explicitly specifies **who** may access the resource by including a mandatory `"Principal"` block alongside `Action` and `Resource`.
- **Decision Engine in Task 4:**
  - **Request 1 (`internal/roster.txt`):** Decided by the **Union of Allows**. The analyst's identity policy permitted reading all objects (`Resource: "*"`), and the bucket resource policy statement `AllowAnalystInternal` explicitly permitted reading `internal/*`. Because neither policy denied the request and both allowed it, access was granted.
  - **Request 2 (`confidential/record.txt`):** Decided by the **Resource-Based Policy's Explicit Deny** (`DenyAnalystConfidential`). Although the analyst's identity policy permitted reading the object, the bucket policy contained an explicit `"Effect": "Deny"` scoped to `confidential/*`. Under the AWS Access Evaluation Engine:
    $$\text{Explicit Deny} > \text{Explicit Allow} > \text{Default Deny}$$
    The explicit Deny in the resource policy overrides the identity policy, terminating the request.

---

#### Question 3:
**Block Public Access is described as a guardrail rather than a control. What is the difference, and why does the distinction matter for an organisation with many engineers?**

- **Control vs. Guardrail:**
  - A **Security Control** is a specific technical configuration applied to an individual resource (e.g., writing a least-privilege bucket policy or removing a public ACL). Controls are mutable and vulnerable to human error; an engineer deploying an infrastructure update can easily modify or overwrite a policy.
  - A **Guardrail** (such as S3 Block Public Access or AWS Organizations Service Control Policies - SCPs) is an immutable governance overlay. It does not replace resource policies; rather, it enforces organizational security boundaries that cannot be bypassed by local administrators or resource-level policies.
- **Significance in Multi-Engineer Organizations:** In large enterprises with hundreds of software developers, DevOps engineers, and automated CI/CD pipelines deploying infrastructure via Terraform or CloudFormation, configuration mistakes are inevitable. A developer might write `"Principal": "*"` to quickly test a webhook or public asset upload. 
- Without a guardrail, that mistake instantly results in a public data breach. With **Block Public Access enabled at the account level**, the guardrail acts as an automated safety net: even if an engineer pushes an insecure policy, S3 intercepts the call at the control plane and refuses to serve public requests, preventing human error from becoming a security incident.

---

#### Question 4:
**Your bucket has default SSE-KMS encryption. Does that protect the confidential record from the analyst in Task 4? Explain precisely what server-side encryption does and does not defend against.**

- **Does it protect against the analyst?** **No.** Default SSE-KMS alone does **not** protect the confidential record from the analyst. If the analyst possesses valid IAM permissions to read the S3 object (`s3:GetObject`) and also has permission to invoke `kms:Decrypt` on the backing KMS CMK, S3 transparently decrypts the ciphertext and returns the plaintext to the analyst.
- **What SSE-KMS Defends Against:**
  - Physical media theft from cloud datacenters (e.g., an unauthorized technician pulling hard drives or SSDs).
  - Data remanence at the storage hypervisor layer (unauthorized access to discarded physical sectors).
  - Out-of-band access bypassing the S3 control plane.
  - Compliance audits mandating encryption at rest (HIPAA, PCI-DSS, ISO 27001).
  - Insider threats at the cloud provider level (AWS datacenter personnel cannot read encrypted data without KMS keys).
- **What SSE-KMS Does NOT Defend Against:**
  - Authorized principals possessing both S3 read and KMS decrypt privileges (such as a compromised analyst account).
  - Misconfigured S3 bucket policies that expose objects to unauthorized users who also have KMS access.
  - Application-level compromises (e.g., SQL injection or SSRF where the application reads decrypted objects on behalf of an attacker).
  - Data exfiltration occurring after the object has been retrieved through valid API channels.

---

#### Question 5:
**A patient invokes their right to erasure. Using your Task 7 evidence, explain why `delete-object` alone is not compliant, and describe two mechanisms that would make the deletion provable.**

- **Why `delete-object` Alone is Non-Compliant:**
  - As demonstrated in Task 7, executing `aws s3api delete-object` on a version-enabled bucket does not destroy or overwrite the data payload. Instead, S3 merely inserts a **Delete Marker** as the current object version (`IsLatest: true`).
  - While standard GET requests return `NoSuchKey` (HTTP 404), the underlying historical versions remain intact. By supplying the exact version ID (`--version-id null`), we retrieved the unredacted patient diagnosis in plaintext (`recovered.txt`).
  - Under **GDPR Article 17** ("Right to be Forgotten") and the **Malaysian PDPA 2010 Retention Principle**, retaining retrievable personal data after an erasure request is illegal and subject to severe regulatory penalties.
- **Two Mechanisms for Provable Deletion:**
  1. **Targeted Per-Version Deletion:** Explicitly invoking `s3api delete-object --version-id <ID>` for every historical revision and delete marker. S3 completely purges the metadata pointer and unlinks the storage blocks, making the object permanently unrecoverable via any API call.
  2. **Cryptographic Erasure (Crypto-Shredding):** In architectures where objects are encrypted using per-patient or per-category KMS keys, permanently deleting the specific KMS key (`kms schedule-key-deletion` or deleting key material in an HSM). Without the key, the ciphertext stored across all versions, replicas, and snapshots becomes computationally unrecoverable random noise, providing auditors with mathematical certainty of destruction.

---

#### Question 6:
**You are the auditor in Week 11. Name three commands from this lab whose output you would collect as compliance evidence, and state which control each one evidences.**

| Compliance Command | Target Output / Evidence Collected | Security Control & Framework Evidenced |
| :--- | :--- | :--- |
| **`aws s3api get-public-access-block --bucket $BUCKET`** | JSON document showing `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets` all set to **`true`**. | **Preventative Exposure Control & Cloud Perimeter Defense** (CSA CCSK v5 Domain 5, ISO/IEC 27017 Section 9.4.1). Proves bucket cannot be made publicly accessible. |
| **`aws s3api get-bucket-encryption --bucket $BUCKET`** | JSON configuration confirming `ApplyServerSideEncryptionByDefault` with `SSEAlgorithm: "aws:kms"`, customer KMS Key ID, and `BucketKeyEnabled: true`. | **Cryptographic Data Protection at Rest** (NIST SP 800-53 SC-28, HIPAA Security Rule § 164.312(a)(2)(iv)). Proves all data ingested is encrypted under a customer-managed key. |
| **`aws s3api get-bucket-lifecycle-configuration --bucket $BUCKET`** | Lifecycle rules table confirming automated expiration of active objects at 365 days and purging of noncurrent versions at 30 days. | **Data Retention & Sanitization Governance** (GDPR Article 5(1)(e) Storage Limitation, PDPA 2010 Retention Principle, NIST SP 800-88). Proves automated compliance with retention schedules. |

---

### Deliverable 4: Verification Command Block Output

To prove the bucket's final security posture, the consolidated verification script was executed:

```bash
echo "=== IKB42603 Lab 6 verification: $BUCKET ==="
aws $EP s3api get-public-access-block --bucket $BUCKET \
  --query 'PublicAccessBlockConfiguration' --output text
aws $EP s3api get-bucket-versioning --bucket $BUCKET --output text
aws $EP s3api get-bucket-encryption --bucket $BUCKET \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyID]' \
  --output text
aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID,Status]' --output text
aws $EP kms describe-key --key-id $KEY_ID --query 'KeyMetadata.KeyState' --output text
```

#### Verification Terminal Transcript:
```text
=== IKB42603 Lab 6 verification: miit-patient-records-3104 ===
True    True    True    True
Enabled
aws:kms arn:aws:kms:us-east-1:000000000000:key/8eceab89-3cc3-4335-a99b-72898a1c6fcc
RetireConfidentialRecords       Enabled
AbortIncompleteUploads          Enabled
PendingDeletion
```

#### Security Posture Analysis:
1. **Public Access Block:** All four flags evaluate to `True`, verifying complete isolation from anonymous internet probing.
2. **Versioning:** Reported as `Enabled`, ensuring data integrity and version control.
3. **Default Encryption:** Confirmed as `aws:kms` backed by CMK `8eceab89-3cc3-4335-a99b-72898a1c6fcc`.
4. **Lifecycle Governance:** Both automated retention rules (`RetireConfidentialRecords` and `AbortIncompleteUploads`) are `Enabled`.
5. **Key State:** Verified as `PendingDeletion`, demonstrating successful cryptographic erasure.

---

## Security Best-Practices Checklist

The following audit checklist summarizes the security baseline established in this laboratory:

- [x] **Every object carries a classification tag before any access decision is made.** Verified in Task 1 with `classification=public`, `internal`, and `confidential`.
- [x] **No bucket policy names Principal: "*"; anonymous access was tested and is refused.** Verified in Task 2 & Task 3; wildcard public policies were identified, removed, and replaced with scoped principals.
- [x] **Block Public Access is enabled on all four flags.** Verified in Task 3 and Deliverable 4 (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets` all `true`).
- [x] **Access is granted by least privilege and scoped to a key prefix, never to /* by default.** Verified in Task 3 and Task 4; policies explicitly scope permissions to `internal/*` or `confidential/*`.
- [x] **Default encryption at rest is aws:kms with a customer-managed key.** Verified in Task 5 with CMK `8eceab89-3cc3-4335-a99b-72898a1c6fcc` and S3 Bucket Keys enabled.
- [x] **Sharing uses time-bounded presigned URLs, not permanent public objects.** Verified in Task 6 using HMAC-SHA256 presigned URLs with 60-second expiration.
- [x] **Versioning is enabled, and the team understands that delete markers do not destroy data.** Verified in Task 7; data remanence was demonstrated and mitigated via targeted per-version deletions.
- [x] **A lifecycle configuration expresses the retention policy, and cryptographic erasure is available for provable deletion.** Verified in Task 8 with automated S3 lifecycle rules and KMS key deletion.

---

## Cleanup & Teardown Procedures

To prevent orphan cloud resources and prevent persistent cloud compute charges, resources must be dismantled in the proper dependency order. A versioned bucket cannot be deleted using standard `s3 rb --force` because noncurrent versions and delete markers survive force commands.

```bash
# 1. Remove bucket resource policy
aws $EP s3api delete-bucket-policy --bucket $BUCKET

# 2. Delete all historical object versions
aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
  list-object-versions --bucket $BUCKET --output json \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

# 3. Delete all delete markers
aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
  list-object-versions --bucket $BUCKET --output json \
  --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}')"

# 4. Verify bucket is completely empty and delete bucket
aws $EP s3api list-object-versions --bucket $BUCKET --output text
aws $EP s3api delete-bucket --bucket $BUCKET

# 5. Clean up IAM user and inline policy
aws $EP iam delete-user-policy --user-name DataAnalyst --policy-name S3ReadAll
aws $EP iam delete-user --user-name DataAnalyst

# 6. Terminate LocalStack container and remove local scratch files
docker rm -f localstack
rm -f *.json *.txt
```

---

## Expansion Ideas & Advanced Cloud Security Implementations

### 1. S3 Object Lock & Compliance-Mode WORM Storage
For highly regulated healthcare and financial records, organizations must protect audit logs from deletion by any identity—including root administrators. **S3 Object Lock** implements Write-Once-Read-Many (WORM) storage:
- **Governance Mode:** Prevents object deletion unless an identity holds the special `s3:BypassGovernanceRetention` permission.
- **Compliance Mode:** An absolute, immutable lock. Neither IAM users, roles, nor the root account can delete the object or reduce the retention period until the retention window expires. This serves as critical audit evidence for SEC Rule 17a-4 and HIPAA requirements.

### 2. Automated Cloud Security Posture Management (CSPM) Script
A lightweight Python CSPM script can monitor and alert on unhardened S3 buckets across an organization:
```python
import boto3

s3 = boto3.client('s3')
buckets = s3.list_buckets()['Buckets']

for b in buckets:
    name = b['Name']
    try:
        bpa = s3.get_public_access_block(Bucket=name)
        cfg = bpa['PublicAccessBlockConfiguration']
        if not all(cfg.values()):
            print(f"[ALERT] Bucket {name} has incomplete Block Public Access!")
    except Exception:
        print(f"[CRITICAL] Bucket {name} has NO Block Public Access configured!")
```

### 3. Infrastructure as Code (IaC) with Automated Security Scanning
Provisioning the hardened bucket using **Terraform** allows security guardrails to be validated pre-deployment using static analysis tools such as **Checkov** or **tfsec**:
```hcl
resource "aws_s3_bucket" "patient_records" {
  bucket = "miit-patient-records-hardened"
}

resource "aws_s3_bucket_public_access_block" "bpa" {
  bucket                  = aws_s3_bucket.patient_records.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.patient_records.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}
```

### 4. Client-Side Encryption vs. SSE-KMS Threat Modeling
While SSE-KMS secures data at rest in the cloud datacenter, data is still transmitted in plaintext over the TLS connection and processed unencrypted in cloud memory. **Client-Side Encryption** (using tools such as the AWS Encryption SDK or OpenSSL) encrypts data on the client device *before* transmission.
- **SSE-KMS Threat Model:** Protects against physical drive loss, hypervisor remanence, and cloud datacenter snooping. Does not protect against insider threats at the cloud provider who hold hypervisor access.
- **Client-Side Threat Model:** Protects data end-to-end, including from the cloud provider itself. The cloud provider stores only unintelligible ciphertext and never possesses the decryption keys.

---

## References & Standard Citations

1. **National Institute of Standards and Technology (NIST):**
   - *NIST SP 800-88 Rev. 1:* Guidelines for Media Sanitization (Cryptographic Erasure & Sanitization Terminology).
   - *NIST SP 800-207:* Zero Trust Architecture (Continuous Evaluation and Explicit Access Validation).
   - *NIST SP 800-53 Rev. 5:* Security and Privacy Controls for Information Systems and Organizations.
2. **International Organization for Standardization (ISO):**
   - *ISO/IEC 27017:2015:* Code of practice for information security controls based on ISO/IEC 27002 for cloud services.
   - *ISO/IEC 27001:2022:* Information security, cybersecurity and privacy protection — Information security management systems.
3. **Cloud Security Alliance (CSA):**
   - *Security Guidance for Critical Areas of Focus in Cloud Computing v5.0:* Domain 4 (Governance & Organization), Domain 5 (Data Security), Domain 9 (Application Security).
4. **Malaysian Communications and Multimedia Commission (MCMC):**
   - *MCMC MTSFB TC G017:2021:* Information Security Requirements for Cloud Service Providers.
5. **Legislative & Regulatory Mandates:**
   - *Personal Data Protection Act (PDPA) 2010 (Malaysia):* Act 709, Security Principle & Retention Principle.
   - *General Data Protection Regulation (GDPR):* Regulation (EU) 2016/679, Article 17 (Right to Erasure) & Article 32 (Security of Processing).
6. **Amazon Web Services (AWS) Technical Documentation:**
   - *Amazon S3 Security Best Practices:* [AWS Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html).
   - *Amazon S3 Versioning & Lifecycle Configurations:* [AWS User Guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html).
   - *AWS KMS Envelope Encryption & S3 Bucket Keys:* [AWS KMS Documentation](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping).
