# TRH-SDK Deployment Architecture - Security Analysis

## Executive Summary

This document provides a comprehensive security analysis of the **Tokamak Rollup Hub SDK** (trh-sdk), focusing on deployment architecture, threat modeling, and vulnerability assessment. Special emphasis is placed on the **AWS Parent Compromise** scenario—analyzing what an attacker could achieve if they gain control of the AWS infrastructure.

> [!CAUTION]
> This analysis reveals several **critical security weaknesses** in the current architecture, particularly around key management and secret storage. These should be addressed before any mainnet deployment.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Component Deep Dive](#component-deep-dive)
3. [Security Boundaries](#security-boundaries)
4. [Threat Model: AWS Parent Compromise](#threat-model-aws-parent-compromise)
5. [Vulnerability Analysis](#vulnerability-analysis)
6. [Blast Radius Analysis](#blast-radius-analysis)
7. [Attack Vectors & Scenarios](#attack-vectors--scenarios)
8. [Recommendations](#recommendations)

---

## Architecture Overview

```mermaid
flowchart TB
    subgraph User["👤 Operator"]
        CLI["trh-sdk CLI"]
        LocalFS["Local Filesystem<br/>(settings.json)"]
    end

    subgraph Ethereum["⛓️ Ethereum L1"]
        L1Contracts["L1 Smart Contracts"]
        L1RPC["L1 RPC Provider"]
        Beacon["Beacon Chain"]
    end

    subgraph AWS["☁️ AWS Cloud"]
        subgraph IAM["Identity & Access"]
            IAMUser["IAM User"]
            IAMRole["IAM Role"]
        end

        subgraph Storage["Storage Layer"]
            S3State["S3 Terraform State"]
            S3Backup["S3 Backups"]
        end

        subgraph Network["Network Layer"]
            VPC["VPC"]
            ALB["Application Load Balancer"]
            SG["Security Groups"]
        end

        subgraph Compute["Compute Layer (EKS)"]
            subgraph Pods["Kubernetes Pods"]
                OpGeth["op-geth<br/>(Sequencer)"]
                OpNode["op-node<br/>(Rollup Driver)"]
                Batcher["op-batcher"]
                Proposer["op-proposer"]
                Challenger["op-challenger"]
            end
            PVC["Persistent Volumes"]
            Secrets["K8s Secrets"]
        end
    end

    CLI -->|"Stores keys"| LocalFS
    CLI -->|"Terraform/kubectl"| AWS
    LocalFS -.->|"Contains"| Keys["🔑 Private Keys"]
    
    OpGeth -->|"Sequences txs"| L1Contracts
    Batcher -->|"Posts batches"| L1Contracts
    Proposer -->|"Posts state roots"| L1Contracts
```

### Deployment Modes

| Mode | Infrastructure | Trust Model | Risk Level |
|------|---------------|-------------|------------|
| **Local Devnet** | Docker Compose | Fully trusted | 🟢 Low |
| **Testnet** | AWS EKS | Semi-trusted | 🟡 Medium |
| **Mainnet** | AWS EKS | Zero-trust required | 🔴 High |

---

## Component Deep Dive

### 1. CLI Tool (`trh-sdk`)

The CLI is a Go binary that orchestrates the entire deployment.

**Security-relevant operations:**

```go
// From pkg/types/configuration.go
type Config struct {
    AdminPrivateKey      string `json:"admin_private_key"`
    SequencerPrivateKey  string `json:"sequencer_private_key"`
    BatcherPrivateKey    string `json:"batcher_private_key"`
    ProposerPrivateKey   string `json:"proposer_private_key"`
    ChallengerPrivateKey string `json:"challenger_private_key,omitempty"`
    // AWS credentials also stored...
    AWS *AWSConfig `json:"aws,omitempty"`
}
```

> [!WARNING]
> **Critical Finding:** All private keys are stored in plaintext in `settings.json` with `0644` permissions.

### 2. Operator Keys

| Key | Purpose | Compromise Impact |
|-----|---------|-------------------|
| **Admin** | Deploy/upgrade contracts, change system params | 🔴 **CRITICAL** - Full system control |
| **Sequencer** | Order and sign L2 blocks | 🔴 **CRITICAL** - Transaction censorship, MEV extraction |
| **Batcher** | Submit L2 batch data to L1 | 🟡 **HIGH** - L2 liveness |
| **Proposer** | Submit state roots to L1 | 🔴 **CRITICAL** - Invalid state attacks |
| **Challenger** | Challenge invalid proposals | 🟡 **HIGH** - Unable to prevent fraud |

### 3. AWS Infrastructure

```mermaid
flowchart LR
    subgraph Terraform["Terraform State"]
        Backend["S3 Backend"]
        Lock["DynamoDB Lock"]
    end

    subgraph EKS["EKS Cluster"]
        IRSA["IAM Roles for<br/>Service Accounts"]
        NodeGroup["EC2 Node Group"]
    end

    subgraph K8s["Kubernetes"]
        NS["Namespace"]
        SA["Service Account"]
        Sec["Secrets"]
        Helm["Helm Release"]
    end

    Backend --> EKS
    EKS --> K8s
    SA --> IRSA
```

---

## Security Boundaries

```mermaid
flowchart TB
    subgraph TB1["Trust Boundary 1: Operator Machine"]
        CLI["CLI"]
        Settings["settings.json"]
        AWS_Creds["~/.aws/credentials"]
    end

    subgraph TB2["Trust Boundary 2: AWS Account"]
        IAM["IAM"]
        S3["S3"]
        EKS["EKS"]
    end

    subgraph TB3["Trust Boundary 3: Kubernetes Cluster"]
        Pods["Pods"]
        Secrets["Secrets"]
        PVC["PVCs"]
    end

    subgraph TB4["Trust Boundary 4: L1 Ethereum"]
        Contracts["L1 Contracts"]
    end

    TB1 ==>|"AWS API"| TB2
    TB2 ==>|"kubectl"| TB3
    TB3 ==>|"RPC"| TB4

    style TB1 fill:#f9d423
    style TB2 fill:#ff6b6b
    style TB3 fill:#4ecdc4
    style TB4 fill:#45b7d1
```

### Trust Boundary Violations

1. **TB1 → TB3**: Private keys flow from operator machine directly into K8s secrets
2. **TB2 → TB3**: AWS credentials embedded in pods for logging/backups
3. **No isolation**: All operator keys share the same security context

---

## Threat Model: AWS Parent Compromise

> [!IMPORTANT]
> **Scenario:** An attacker gains full control of the AWS account via:
> - Stolen IAM credentials
> - Compromised CI/CD pipeline (GitHub Actions secrets)
> - Insider threat
> - Supply chain attack

### What the Attacker Controls

```mermaid
flowchart TB
    subgraph Compromised["🔴 COMPROMISED (AWS Parent)"]
        IAM["IAM Users/Roles"]
        S3["S3 Buckets"]
        EKS["EKS Control Plane"]
        EC2["EC2 Nodes"]
        K8sSecrets["K8s Secrets"]
        PVC["Persistent Volumes"]
        ALB["Load Balancer"]
    end

    subgraph Immediate["⚡ Immediate Access"]
        PrivKeys["All Private Keys"]
        TFState["Terraform State"]
        DBCreds["Database Credentials"]
        AWSKeys["AWS Access Keys"]
    end

    subgraph Delayed["⏰ Delayed Access"]
        L1Funds["L1 Funds"]
        L2State["L2 State"]
        UserTx["User Transactions"]
    end

    Compromised --> Immediate
    Immediate --> Delayed
```

### Attack Timeline

```mermaid
timeline
    title AWS Compromise Attack Timeline
    T+0 : Attacker gains AWS access
        : Access IAM console
        : List all resources
    T+5min : Extract secrets
        : kubectl get secrets
        : Read settings.json from S3
        : Access Terraform state
    T+15min : Extract private keys
        : Decode K8s secrets
        : All operator keys exposed
    T+30min : L2 exploitation begins
        : Censor transactions
        : Extract MEV
        : Manipulate state roots
    T+1hr : L1 impact
        : Drain operator wallets
        : Submit fraudulent proposals
    T+7days : Challenge period expires
        : Fraudulent state finalized
        : L1 bridge funds at risk
```

---

## Vulnerability Analysis

### Critical Vulnerabilities

#### 1. Plaintext Key Storage

```go
// pkg/types/configuration.go:172
err = os.WriteFile(fileName, data, 0644)  // World-readable!
```

**File contents:**
```json
{
  "admin_private_key": "0x...",
  "sequencer_private_key": "0x...",
  "batcher_private_key": "0x...",
  "proposer_private_key": "0x..."
}
```

| Aspect | Risk |
|--------|------|
| Storage location | Local filesystem, S3 backups |
| Encryption | ❌ None |
| Access control | ❌ File permissions only (0644) |
| Key rotation | ❌ No mechanism |

#### 2. Seed Phrase Exposure

```go
// pkg/stacks/thanos/input.go:254-259
fmt.Print("Please enter your admin seed phrase: ")
seed, err := scanner.ScanString()  // Plaintext input!
```

- Seed phrase entered in terminal (may be logged)
- Derived keys stored without encryption
- No hardware wallet support

#### 3. AWS Credentials in Plain Config

```go
// pkg/stacks/thanos/monitoring.go:659
"secretKey": t.deployConfig.AWS.SecretKey,  // Embedded in pod config
```

AWS credentials are:
- Stored in `settings.json`
- Passed to Helm values
- Embedded in pod environment variables
- Visible in Kubernetes secrets

#### 4. No Secret Rotation

- No mechanism to rotate keys
- Compromised key = permanent access
- No audit trail for key usage

### High-Risk Vulnerabilities

| Vulnerability | Impact | Exploitability |
|---------------|--------|----------------|
| K8s secrets unencrypted at rest | Key extraction | Easy with AWS access |
| Terraform state contains secrets | State rollback attacks | Easy with S3 access |
| No network policies | Pod-to-pod lateral movement | Easy from any pod |
| Helm values in ConfigMaps | Credential exposure | Easy with K8s access |
| No pod security policies | Container escape | Medium |

---

## Blast Radius Analysis

### If Attacker Compromises...

```mermaid
flowchart TB
    subgraph AWS["AWS Account Compromise"]
        FULL["💀 TOTAL SYSTEM COMPROMISE"]
    end

    subgraph Keys["Individual Key Compromise"]
        Admin["Admin Key"] --> AdminImpact["• Upgrade contracts<br/>• Change system params<br/>• Drain admin wallet"]
        Sequencer["Sequencer Key"] --> SeqImpact["• Censor transactions<br/>• Extract MEV<br/>• Control block ordering"]
        Batcher["Batcher Key"] --> BatchImpact["• Halt L2 liveness<br/>• Drain batcher wallet"]
        Proposer["Proposer Key"] --> PropImpact["• Submit invalid roots<br/>• Steal bridged funds*"]
    end

    AWS --> Admin
    AWS --> Sequencer
    AWS --> Batcher
    AWS --> Proposer

    note["*After challenge period if challenger also compromised"]
```

### Impact Matrix

| Compromised Component | L2 Liveness | L2 Safety | L1 Funds | User Funds |
|-----------------------|-------------|-----------|----------|------------|
| AWS Account | 🔴 | 🔴 | 🔴 | 🔴 |
| Admin Key | 🟡 | 🔴 | 🟡 | 🔴 |
| Sequencer Key | 🔴 | 🟡 | 🟢 | 🟡 |
| Batcher Key | 🔴 | 🟢 | 🟢 | 🟢 |
| Proposer Key | 🟢 | 🔴 | 🔴 | 🔴 |
| Challenger Key | 🟢 | 🔴 | 🔴 | 🔴 |

Legend: 🔴 Critical | 🟡 High | 🟢 Low/None

---

## Attack Vectors & Scenarios

### Scenario 1: Silent State Manipulation

```mermaid
sequenceDiagram
    participant Attacker
    participant AWS
    participant L2 as L2 Chain
    participant L1 as L1 Contract

    Attacker->>AWS: Compromise via leaked IAM creds
    AWS->>Attacker: Full access to EKS
    Attacker->>AWS: kubectl get secret -o yaml
    AWS->>Attacker: All private keys exposed
    
    Note over Attacker: Extract proposer key
    
    Attacker->>L2: Create fraudulent L2 block
    Attacker->>L1: Submit invalid state root (as proposer)
    
    Note over L1: 7-day challenge period starts
    
    Attacker->>AWS: Also extract challenger key
    Note over Attacker: Don't challenge own fraud
    
    L1->>L1: Challenge period expires
    Note over L1: 💀 FRAUD FINALIZED
    
    Attacker->>L1: Withdraw bridge funds using fake proofs
```

### Scenario 2: MEV Extraction & Censorship

```mermaid
flowchart LR
    subgraph Attack["Attacker Actions"]
        A1["Extract sequencer key"]
        A2["Run shadow sequencer"]
        A3["Front-run all DEX trades"]
        A4["Censor competitor transactions"]
        A5["Sandwich attack every swap"]
    end

    A1 --> A2 --> A3 --> A4 --> A5
    
    subgraph Impact["User Impact"]
        I1["Massive slippage losses"]
        I2["Transactions stuck"]
        I3["Unable to exit positions"]
    end

    A5 --> Impact
```

### Scenario 3: Supply Chain Attack via CI/CD

```mermaid
flowchart TB
    subgraph GitHub["GitHub Actions"]
        Secrets["Secrets:<br/>DOCKERHUB_USERNAME<br/>DOCKERHUB_TOKEN"]
        Workflow["docker-build-push.yml"]
    end

    subgraph Attack["Attack Vector"]
        Malicious["Malicious PR with<br/>modified Dockerfile"]
        Backdoor["Backdoored trh-sdk image"]
    end

    subgraph Victims["All Users"]
        User1["Chain Operator 1"]
        User2["Chain Operator 2"]
        User3["Chain Operator N"]
    end

    Secrets --> Workflow
    Malicious --> Workflow
    Workflow --> Backdoor
    Backdoor --> User1
    Backdoor --> User2
    Backdoor --> User3
```

---

## Recommendations

### Immediate Actions (P0)

#### 1. Implement Secret Encryption

```diff
- err = os.WriteFile(fileName, data, 0644)
+ encryptedData := encryptWithKMS(data, kmsKeyId)
+ err = os.WriteFile(fileName, encryptedData, 0600)
```

#### 2. Use AWS KMS for Key Management

```mermaid
flowchart LR
    subgraph Current["Current (Insecure)"]
        Plain["Plaintext keys in K8s secrets"]
    end

    subgraph Recommended["Recommended"]
        KMS["AWS KMS"]
        ESO["External Secrets Operator"]
        SM["AWS Secrets Manager"]
    end

    Current -.->|"Migrate to"| SM
    SM --> ESO
    ESO --> Pods
    KMS --> SM
```

#### 3. Separate Key Management Per Role

| Key | Storage | Access Pattern |
|-----|---------|----------------|
| Admin | Hardware wallet / Cold storage | Manual multi-sig |
| Sequencer | AWS KMS with IRSA | Service account only |
| Batcher | AWS KMS with IRSA | Service account only |
| Proposer | AWS KMS with IRSA | Service account only |
| Challenger | Separate AWS account | Air-gapped |

### Short-term Actions (P1)

| Action | Effort | Impact |
|--------|--------|--------|
| Enable K8s secrets encryption at rest | Low | High |
| Implement network policies | Medium | High |
| Add pod security standards | Medium | Medium |
| Rotate all credentials regularly | Low | High |
| Implement audit logging | Low | High |

### Long-term Actions (P2)

1. **Multi-sig for Admin Key**
   - Require 3-of-5 signatures for contract upgrades
   
2. **Decentralized Sequencing**
   - Multiple independent sequencers
   - No single point of failure

3. **Hardware Security Modules (HSM)**
   - AWS CloudHSM for key operations
   - Never expose raw private keys

4. **Zero-Trust Architecture**
   ```mermaid
   flowchart TB
       subgraph ZeroTrust["Zero Trust Model"]
           Identity["Identity Verification"]
           MicroSeg["Micro-segmentation"]
           LeastPriv["Least Privilege"]
           Encrypt["Encrypt Everything"]
       end
   ```

---

## Risk Summary

| Risk Category | Current State | Target State |
|---------------|---------------|--------------|
| Key Management | 🔴 Critical | 🟢 HSM-backed |
| Secret Storage | 🔴 Critical | 🟢 Encrypted + KMS |
| Access Control | 🟡 Weak | 🟢 RBAC + Network Policies |
| Audit Trail | 🔴 None | 🟢 CloudTrail + EKS Audit |
| Incident Response | 🔴 None | 🟢 Runbooks + Auto-remediation |

---

## Detailed Mitigation Strategies

### 1. Key Management Mitigation

**Current Problem:** Private keys stored in plaintext `settings.json` file with world-readable permissions.

**Why This Is Critical:**
- Anyone with filesystem access can read all operator keys
- Keys are copied to K8s secrets without encryption
- No separation between different key roles
- Single point of compromise = total system loss

**Mitigation Approach:**

#### Step 1: Use AWS KMS for Key Encryption

```go
// BEFORE (Insecure)
type Config struct {
    AdminPrivateKey string `json:"admin_private_key"`  // Plaintext!
}

// AFTER (Secure)
type Config struct {
    AdminPrivateKeyEncrypted string `json:"admin_private_key_encrypted"`
    KMSKeyARN                string `json:"kms_key_arn"`
}

// Decrypt only when needed
func (c *Config) GetAdminPrivateKey(ctx context.Context) (string, error) {
    kmsClient := kms.NewFromConfig(awsCfg)
    result, err := kmsClient.Decrypt(ctx, &kms.DecryptInput{
        CiphertextBlob: base64Decode(c.AdminPrivateKeyEncrypted),
        KeyId:          aws.String(c.KMSKeyARN),
    })
    return string(result.Plaintext), err
}
```

#### Step 2: Implement AWS Secrets Manager Integration

```mermaid
flowchart LR
    subgraph Before["Before (Insecure)"]
        File["settings.json"] --> Pod["Pod reads plaintext"]
    end

    subgraph After["After (Secure)"]
        SM["AWS Secrets Manager"] --> ESO["External Secrets Operator"]
        ESO --> K8sSecret["K8s Secret (encrypted)"]
        K8sSecret --> SecurePod["Pod"]
        KMS["AWS KMS"] --> SM
    end
```

**Implementation Steps:**

1. **Create KMS Key:**
   ```bash
   aws kms create-key --description "TRH-SDK Operator Keys" \
     --key-usage ENCRYPT_DECRYPT \
     --origin AWS_KMS
   ```

2. **Store in Secrets Manager:**
   ```bash
   aws secretsmanager create-secret \
     --name "trh-sdk/operator-keys" \
     --secret-string '{"sequencer":"0x...","batcher":"0x..."}' \
     --kms-key-id alias/trh-sdk-keys
   ```

3. **Install External Secrets Operator:**
   ```bash
   helm install external-secrets external-secrets/external-secrets \
     -n external-secrets --create-namespace
   ```

4. **Create ExternalSecret Resource:**
   ```yaml
   apiVersion: external-secrets.io/v1beta1
   kind: ExternalSecret
   metadata:
     name: operator-keys
   spec:
     refreshInterval: 1h
     secretStoreRef:
       name: aws-secrets-manager
       kind: ClusterSecretStore
     target:
       name: operator-keys
     data:
       - secretKey: sequencer-key
         remoteRef:
           key: trh-sdk/operator-keys
           property: sequencer
   ```

#### Step 3: Hardware Wallet for Admin Key

**Why:** Admin key should NEVER be on any server.

```mermaid
flowchart TB
    subgraph ColdStorage["Cold Storage (Admin Key)"]
        HW["Hardware Wallet<br/>(Ledger/Trezor)"]
        MultiSig["3-of-5 Multi-sig"]
    end

    subgraph HotKeys["Hot Keys (Automated)"]
        KMS1["Sequencer Key in KMS"]
        KMS2["Batcher Key in KMS"]
        KMS3["Proposer Key in KMS"]
    end

    subgraph Ops["Operations"]
        Deploy["Contract Deployment"] --> HW
        Upgrade["Contract Upgrade"] --> MultiSig
        BatchSubmit["Batch Submission"] --> KMS2
    end
```

---

### 2. Secret Storage Mitigation

**Current Problem:** Secrets visible in multiple places without encryption.

**Locations Where Secrets Are Exposed:**
1. `settings.json` on local machine
2. S3 backups (if configured)
3. Terraform state in S3
4. Kubernetes secrets (base64, not encrypted)
5. Pod environment variables
6. CloudWatch logs (potentially)

**Mitigation Approach:**

#### Enable EKS Secrets Encryption

```bash
# Create encryption config
aws eks update-cluster-config \
  --name thanos-cluster \
  --encryption-config '[{
    "provider": {"keyArn": "arn:aws:kms:us-east-1:123456789:key/abc123"},
    "resources": ["secrets"]
  }]'
```

#### Encrypt Terraform State

```hcl
# backend.tf
terraform {
  backend "s3" {
    bucket         = "trh-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true  # Enable server-side encryption
    kms_key_id     = "arn:aws:kms:us-east-1:123456789:key/abc123"
    dynamodb_table = "terraform-locks"
  }
}
```

#### Prevent Secret Logging

```yaml
# Pod spec with secret masking
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: op-batcher
      env:
        - name: BATCHER_PRIVATE_KEY
          valueFrom:
            secretKeyRef:
              name: operator-keys
              key: batcher-key
      # Never echo secrets in logs
      command:
        - /bin/sh
        - -c
        - |
          # Mask secrets in process list
          exec /app/op-batcher --private-key-file=/secrets/key
```

---

### 3. Access Control Mitigation

**Current Problem:** No RBAC, no network policies, pods can access everything.

**Mitigation Approach:**

#### Kubernetes RBAC

```yaml
# Restrict secret access to specific pods
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: batcher-role
  namespace: thanos-stack
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["batcher-key"]  # Only this secret
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: batcher-binding
subjects:
  - kind: ServiceAccount
    name: batcher-sa
roleRef:
  kind: Role
  name: batcher-role
  apiGroup: rbac.authorization.k8s.io
```

#### Network Policies

```yaml
# Isolate batcher pod - only allow outbound to L1 RPC
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: batcher-network-policy
spec:
  podSelector:
    matchLabels:
      app: op-batcher
  policyTypes:
    - Ingress
    - Egress
  ingress: []  # No inbound allowed
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0  # Allow L1 RPC (external)
      ports:
        - port: 443
          protocol: TCP
    - to:
        - podSelector:
            matchLabels:
              app: op-node  # Allow op-node communication
      ports:
        - port: 8545
```

#### AWS IAM Least Privilege

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": [
        "arn:aws:secretsmanager:*:*:secret:trh-sdk/batcher-key-*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:PrincipalTag/Role": "batcher"
        }
      }
    }
  ]
}
```

---

### 4. Audit Trail Mitigation

**Current Problem:** No logging of who accessed what, when.

**Mitigation Approach:**

#### Enable CloudTrail for All AWS Actions

```hcl
resource "aws_cloudtrail" "trh_audit" {
  name                          = "trh-sdk-audit-trail"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  
  kms_key_id = aws_kms_key.audit.arn
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    
    data_resource {
      type   = "AWS::SecretsManager::Secret"
      values = ["arn:aws:secretsmanager:*:*:secret:trh-sdk/*"]
    }
  }
}
```

#### EKS Audit Logging

```bash
aws eks update-cluster-config \
  --name thanos-cluster \
  --logging '{"clusterLogging":[
    {"types":["api","audit","authenticator","controllerManager","scheduler"],
     "enabled":true}
  ]}'
```

#### CloudWatch Alerts for Suspicious Activity

```yaml
# Alert on secret access from unknown IPs
Resources:
  SecretAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousSecretAccess
      MetricName: SecretAccessCount
      Namespace: TRH-SDK/Security
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref SecurityAlertTopic
```

---

### 5. Incident Response Mitigation

**Current Problem:** No procedures for detecting or responding to breaches.

**Mitigation Approach:**

#### Automated Key Rotation Runbook

```mermaid
flowchart TB
    subgraph Detection["Detection Phase"]
        Alert["CloudWatch Alert"] --> Triage["Security Team Triage"]
        Triage --> Confirm["Confirm Compromise"]
    end

    subgraph Containment["Containment Phase"]
        Confirm --> Revoke["Revoke AWS Credentials"]
        Revoke --> Isolate["Isolate Affected Pods"]
        Isolate --> Preserve["Preserve Forensic Evidence"]
    end

    subgraph Recovery["Recovery Phase"]
        Preserve --> RotateKeys["Rotate All Keys"]
        RotateKeys --> UpdateContracts["Update L1 Contracts"]
        UpdateContracts --> Redeploy["Redeploy Stack"]
    end

    subgraph PostIncident["Post-Incident"]
        Redeploy --> RootCause["Root Cause Analysis"]
        RootCause --> Harden["Implement Fixes"]
    end
```

#### Emergency Key Rotation Script

```bash
#!/bin/bash
# emergency-key-rotation.sh

set -e

echo "🚨 EMERGENCY KEY ROTATION INITIATED"

# 1. Generate new keys
NEW_SEQ_KEY=$(cast wallet new | grep Private | awk '{print $3}')
NEW_BATCH_KEY=$(cast wallet new | grep Private | awk '{print $3}')
NEW_PROP_KEY=$(cast wallet new | grep Private | awk '{print $3}')

# 2. Update Secrets Manager
aws secretsmanager update-secret \
  --secret-id trh-sdk/operator-keys \
  --secret-string "{\"sequencer\":\"$NEW_SEQ_KEY\",\"batcher\":\"$NEW_BATCH_KEY\",\"proposer\":\"$NEW_PROP_KEY\"}"

# 3. Force secret refresh in K8s
kubectl annotate externalsecret operator-keys \
  force-sync=$(date +%s) --overwrite

# 4. Rolling restart of affected pods
kubectl rollout restart deployment/op-batcher -n thanos-stack
kubectl rollout restart deployment/op-proposer -n thanos-stack

# 5. Update L1 contracts with new addresses (requires admin multi-sig)
echo "⚠️  MANUAL STEP: Update SystemConfig with new operator addresses"
echo "   New Sequencer: $(cast wallet address $NEW_SEQ_KEY)"
echo "   New Batcher:   $(cast wallet address $NEW_BATCH_KEY)"
echo "   New Proposer:  $(cast wallet address $NEW_PROP_KEY)"

echo "✅ Emergency rotation complete"
```

#### Incident Response Checklist

| Phase | Action | Owner | Time |
|-------|--------|-------|------|
| **Detection** | Alert triggered in CloudWatch | Automated | T+0 |
| **Detection** | Security team notified via PagerDuty | Automated | T+1m |
| **Triage** | Confirm if genuine compromise | Security Lead | T+15m |
| **Contain** | Revoke compromised IAM credentials | Security Lead | T+20m |
| **Contain** | Scale down affected deployments | DevOps | T+25m |
| **Contain** | Block compromised IPs at ALB | DevOps | T+30m |
| **Recover** | Execute key rotation script | Security Lead | T+45m |
| **Recover** | Multi-sig update L1 contracts | Admin Quorum | T+2h |
| **Recover** | Redeploy with new credentials | DevOps | T+3h |
| **Review** | Root cause analysis | All | T+24h |
| **Harden** | Implement preventive measures | Engineering | T+1w |

---

## Implementation Priority Matrix

| Mitigation | Effort | Impact | Priority |
|------------|--------|--------|----------|
| Enable EKS secrets encryption | 🟢 Low | 🟡 High | **P0** |
| Change file permissions to 0600 | 🟢 Low | 🟡 Medium | **P0** |
| Implement External Secrets Operator | 🟡 Medium | 🔴 Critical | **P0** |
| Add Kubernetes RBAC roles | 🟡 Medium | 🟡 High | **P1** |
| Deploy network policies | 🟡 Medium | 🟡 High | **P1** |
| Enable CloudTrail + EKS audit | 🟢 Low | 🟡 High | **P1** |
| Create incident response runbooks | 🟡 Medium | 🟡 Medium | **P1** |
| Migrate to AWS CloudHSM | 🔴 High | 🔴 Critical | **P2** |
| Implement admin multi-sig | 🔴 High | 🔴 Critical | **P2** |
| Decentralize sequencer | 🔴 Very High | 🔴 Critical | **P3** |

---

> [!CAUTION]
> **Do not deploy to mainnet** until at least P0 recommendations are implemented. Current architecture has multiple critical vulnerabilities that could result in total loss of funds.
