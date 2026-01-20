# Tokamak Rollup Hub SDK - Deployment Architecture

This document provides a comprehensive visual overview of the TRH-SDK deployment architecture.

---

## Glossary of Terms

Before diving into the architecture, here's an explanation of all technical terms used in this document:

### Infrastructure Components

| Term | Full Name | Description |
|------|-----------|-------------|
| **CLI** | Command Line Interface | The `trh-sdk` tool you run in your terminal to deploy and manage your L2 chain |
| **Docker Compose** | Docker Compose | A tool for defining and running multi-container Docker applications locally |
| **AWS** | Amazon Web Services | Cloud computing platform used for production deployments |
| **VPC** | Virtual Private Cloud | An isolated virtual network within AWS where all your resources run securely |
| **EKS** | Elastic Kubernetes Service | AWS-managed Kubernetes service that runs your containerized applications |
| **S3** | Simple Storage Service | AWS object storage used for Terraform state and backups |
| **ALB** | Application Load Balancer | AWS load balancer that distributes incoming traffic to your pods |
| **Infra** | Infrastructure | The underlying cloud resources (VPC, EKS, S3) that host your L2 chain |

### Kubernetes (K8s) Terms

| Term | Description |
|------|-------------|
| **K8s** | Short for Kubernetes - container orchestration platform that manages your application pods |
| **Pods** | The smallest deployable units in Kubernetes, containing one or more containers |
| **Helm** | Package manager for Kubernetes - used to deploy complex applications with a single command |
| **Helm Charts** | Pre-configured Kubernetes resource templates packaged for easy deployment |
| **Namespace** | Virtual cluster within Kubernetes to isolate resources (e.g., your chain's components) |
| **Ingress** | Kubernetes resource that manages external access to services (HTTP/HTTPS routing) |
| **PVC** | Persistent Volume Claim - request for storage that persists beyond pod restarts |

### Ethereum & L2 Components

| Term | Description |
|------|-------------|
| **L1** | Layer 1 - The base Ethereum blockchain (mainnet or testnet like Sepolia) |
| **L2** | Layer 2 - Your rollup chain built on top of Ethereum for faster, cheaper transactions |
| **L1RPC** | L1 RPC URL - HTTP endpoint to communicate with Ethereum (e.g., Alchemy, Infura) |
| **Beacon** | Beacon Chain RPC - Ethereum's consensus layer endpoint needed for L2 derivation |
| **Contracts** | Smart contracts deployed on L1 that anchor your L2 (bridges, state roots, etc.) |

### L2 Stack Components (Thanos/OP Stack)

| Component | Description |
|-----------|-------------|
| **op-geth** | L2 execution engine - processes transactions and maintains L2 state (fork of go-ethereum) |
| **op-node** | Rollup driver - derives L2 blocks from L1 data and coordinates with op-geth |
| **op-batcher** | Batch submitter - compresses L2 transactions and posts them to L1 as calldata |
| **op-proposer** | State root proposer - submits L2 state roots to L1 for verification |
| **op-challenger** | Fraud prover - monitors proposals and challenges invalid state roots |

### Deployment Terminology

| Term | Description |
|------|-------------|
| **Devnet** | Development network - local Docker-based environment for testing |
| **Testnet** | Test network - deployed to AWS but uses L1 testnet (Sepolia) for testing |
| **Mainnet** | Production network - deployed to AWS using Ethereum mainnet |
| **Terraform** | Infrastructure as Code tool - automates AWS resource provisioning |

### Data Flow Explained

```
Infra --> K8s      = AWS infrastructure hosts the Kubernetes cluster
K8s --> L1RPC      = Kubernetes pods connect to Ethereum L1 via RPC
K8s --> Beacon     = Kubernetes pods connect to Beacon Chain for consensus data
CLI --> Infra      = CLI tool provisions infrastructure via Terraform
CLI --> Contracts  = CLI deploys smart contracts to L1
```

---


## High-Level System Overview

```mermaid
flowchart TB
    subgraph User["👤 User"]
        CLI["trh-sdk CLI"]
    end

    subgraph LocalDev["🖥️ Local Development"]
        Docker["Docker Compose"]
        L1Local["L1 Node (Geth)"]
        L2Local["L2 Node (Thanos)"]
    end

    subgraph AWS["☁️ AWS Cloud"]
        subgraph Infra["Infrastructure Layer"]
            S3["S3 (Terraform State)"]
            VPC["VPC"]
            EKS["EKS Cluster"]
        end
        
        subgraph K8s["Kubernetes Layer"]
            Helm["Helm Charts"]
            L2Pods["L2 Stack Pods"]
            Ingress["ALB Ingress"]
        end
    end

    subgraph Ethereum["⛓️ Ethereum Network"]
        L1RPC["L1 RPC (Alchemy/Infura)"]
        Beacon["Beacon Chain RPC"]
        Contracts["L1 Smart Contracts"]
    end

    CLI -->|"deploy (devnet)"| Docker
    Docker --> L1Local
    Docker --> L2Local
    
    CLI -->|"deploy (testnet/mainnet)"| Infra
    Infra --> K8s
    K8s --> L1RPC
    K8s --> Beacon
    CLI -->|"deploy-contracts"| Contracts
```

---

## Deployment Modes

### 1️⃣ Local Devnet Deployment

```mermaid
flowchart LR
    subgraph CLI["trh-sdk"]
        Deploy["trh-sdk deploy"]
    end

    subgraph Setup["Setup Phase"]
        Clone["Clone tokamak-thanos repo"]
        Env["Set DEVNET_L2OO=true"]
    end

    subgraph Docker["Docker Compose Stack"]
        direction TB
        L1["ops-bedrock-l1-1<br/>(L1 Geth Node)"]
        L2["ops-bedrock-l2-1<br/>(L2 Execution)"]
        OpNode["ops-bedrock-op-node-1<br/>(Rollup Node)"]
        Challenger["ops-bedrock-op-challenger-1<br/>(Fraud Proof)"]
    end

    Deploy --> Clone --> Env
    Env -->|"make devnet-up"| Docker
    L1 <--> L2
    L2 <--> OpNode
    OpNode <--> Challenger
```

### 2️⃣ Testnet/Mainnet AWS Deployment

```mermaid
flowchart TB
    subgraph Phase1["Phase 1: L1 Contract Deployment"]
        DeployContracts["trh-sdk deploy-contracts"]
        Build["Build Configuration"]
        L1Deploy["Deploy to L1"]
        Artifacts["rollup.json + genesis.json"]
    end

    subgraph Phase2["Phase 2: Infrastructure Deployment"]
        DeployStack["trh-sdk deploy"]
        TFBackend["Terraform Backend (S3)"]
        TFStack["Terraform Thanos Stack"]
    end

    subgraph Phase3["Phase 3: Kubernetes Setup"]
        EKSConfig["Configure EKS Access"]
        HelmRepo["Add Helm Repository"]
        HelmInstall["Install Helm Charts"]
    end

    subgraph Phase4["Phase 4: Services"]
        Bridge["Install Bridge"]
        Backup["Initialize Backup System"]
        Ingress["Configure Ingress"]
    end

    DeployContracts --> Build --> L1Deploy --> Artifacts
    Artifacts --> DeployStack
    DeployStack --> TFBackend --> TFStack
    TFStack --> EKSConfig --> HelmRepo --> HelmInstall
    HelmInstall --> Bridge --> Backup --> Ingress
```

---

## AWS Infrastructure Architecture

```mermaid
flowchart TB
    subgraph Internet["🌐 Internet"]
        Users["Users/DApps"]
        L1["Ethereum L1"]
    end

    subgraph AWS["AWS Cloud"]
        subgraph S3Layer["Storage"]
            S3State["S3 Bucket<br/>(Terraform State)"]
            S3Backup["S3 Bucket<br/>(Backups)"]
        end

        subgraph Network["VPC"]
            ALB["Application Load Balancer"]
            
            subgraph EKS["EKS Cluster"]
                subgraph Namespace["K8s Namespace"]
                    OpGeth["op-geth<br/>(L2 Execution)"]
                    OpNode["op-node<br/>(Rollup Driver)"]
                    Batcher["op-batcher<br/>(Batch Submitter)"]
                    Proposer["op-proposer<br/>(State Root Proposer)"]
                    Challenger["op-challenger<br/>(Fraud Prover)"]
                end
                
                subgraph PVC["Persistent Storage"]
                    GethData["Geth Data Volume"]
                end
            end
        end
    end

    Users -->|"RPC Requests"| ALB
    ALB --> OpGeth
    OpGeth <--> OpNode
    OpNode --> Batcher
    OpNode --> Proposer
    Proposer --> Challenger
    Batcher -->|"Submit Batches"| L1
    Proposer -->|"Submit State Roots"| L1
    OpGeth --> GethData
```

---

## CI/CD Pipeline

```mermaid
flowchart LR
    subgraph GitHub["GitHub"]
        Push["Push to main"]
        PR["Pull Request"]
    end

    subgraph Actions["GitHub Actions"]
        CI["CI Workflow"]
        Build["Docker Build"]
        QEMU["QEMU (Multi-arch)"]
    end

    subgraph Registry["Docker Hub"]
        Image["tokamaknetwork/trh-sdk"]
        Tags["Tags:<br/>latest, sha-xxx,<br/>linux/amd64, linux/arm64"]
    end

    Push --> Build
    PR --> CI
    Build --> QEMU --> Image
    Image --> Tags
```

---

## Plugin Architecture

```mermaid
flowchart TB
    subgraph Core["Core Stack"]
        L2["L2 Chain"]
    end

    subgraph Plugins["Optional Plugins"]
        Bridge["🌉 Bridge<br/>(trh-sdk install bridge)"]
        Explorer["🔍 Block Explorer<br/>(trh-sdk install block-explorer)"]
        Monitor["📊 Monitoring<br/>(trh-sdk install monitoring)"]
    end

    subgraph MonitorStack["Monitoring Stack"]
        Prometheus["Prometheus"]
        Grafana["Grafana"]
        Loki["Loki (Logs)"]
        Alerting["Alert Manager"]
    end

    L2 --> Bridge
    L2 --> Explorer
    L2 --> Monitor
    Monitor --> Prometheus
    Monitor --> Grafana
    Monitor --> Loki
    Monitor --> Alerting
```

---

## Key Components Summary

| Component | Technology | Purpose |
|-----------|------------|---------|
| **CLI** | Go (urfave/cli) | User interface for all operations |
| **Infrastructure** | Terraform | Provision AWS resources (VPC, EKS, S3) |
| **Orchestration** | Kubernetes/EKS | Container management |
| **Deployment** | Helm Charts | K8s resource templating |
| **L2 Stack** | tokamak-thanos | OP Stack-based L2 |
| **CI/CD** | GitHub Actions | Automated builds and Docker pushes |
| **Monitoring** | Prometheus/Grafana | Metrics and alerting |

---

## Configuration Files

```mermaid
flowchart LR
    subgraph Config["Configuration"]
        Settings["settings.json"]
        Rollup["rollup.json"]
        Genesis["genesis.json"]
        Envrc[".envrc"]
        Values["thanos-stack-values.yaml"]
    end

    subgraph Usage["Used By"]
        CLI["CLI Commands"]
        TF["Terraform"]
        Helm["Helm"]
        K8s["Kubernetes"]
    end

    Settings --> CLI
    Settings --> TF
    Rollup --> Helm
    Genesis --> Helm
    Envrc --> TF
    Values --> Helm
    Values --> K8s
```
