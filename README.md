# 🛡️ Khandaq (خندق) - AI-Driven Autonomous SOC System

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Agents: 53](https://img.shields.io/badge/AI%20Agents-53-success)
![Status: Production Ready](https://img.shields.io/badge/Status-Production%20Ready-orange)

Welcome to the **AI-Driven Autonomous SOC System**. This project is a complete, enterprise-grade Security Operations Center built entirely on Free and Open-Source Software (FOSS). It features a revolutionary 3-tier artificial intelligence architecture containing **53 Autonomous AI Agents** designed to detect, analyze, and respond to cyber threats in real-time.

---

## 🏛️ Architecture Overview

The system is divided into two main components:
1. **The Infrastructure (Data & Tools):** 34 containerized security tools (Wazuh, Zeek, Suricata, MISP, OpenSearch, DFIR-IRIS, Shuffle, etc.).
2. **The AI Brain (Agents):** 53 Python-based agents utilizing local LLMs (Ollama) to orchestrate detection and response.

### 🧠 The Agent Hierarchy (53 Agents)
The AI brain operates on a military-inspired hierarchy to ensure zero alert fatigue and high accuracy:

*   **👷 47 Worker Agents (Layer 1):** Specialized agents for specific tasks (e.g., `W03` for Ransomware, `W35` for Honeypots, `W39` for Lateral Movement). They collect data, analyze it, and report findings.
*   **👨‍💼 5 Supervisors (Layer 2):** They manage the workers. (Endpoint, Network, Infrastructure, Detection, Response). They correlate alerts from multiple workers (e.g., combining a suspicious DNS query with an unusual process).
*   **👑 1 Commander Agent (Layer 3):** The supreme AI coordinator. It receives escalated, correlated threats from supervisors, adjusts the global DEFCON threat level, and makes high-stakes decisions like isolating an entire subnet.

---

## 🚀 Prerequisites

To run this system, you need a dedicated server or cloud instance (AWS/Azure/GCP) with:
*   **OS:** Ubuntu 22.04 LTS (Recommended) or Debian 11+
*   **CPU:** 8+ Cores (16+ Cores recommended for LLM processing)
*   **RAM:** 32 GB Minimum (64 GB Highly Recommended for OpenSearch + LLMs)
*   **Disk:** 500+ GB SSD (NVMe preferred for fast log indexing)
*   **Network:** Static IP, open ports for ingestion (e.g., 1514 for Wazuh, 9200 for OpenSearch).

---

## ⚙️ Installation & Deployment

Deploying the entire SOC is simplified into a single master script.

1. **Clone/Move the directory** to your Linux server (e.g., `/opt/soc-system`).
2. **Make the installer executable:**
   ```bash
   cd /opt/soc-system
   sudo chmod +x install.sh
   ```
3. **Run the Master Installer:**
   ```bash
   sudo ./install.sh
   ```
   *The script will automatically install Docker, pull all 34 containers, configure networking, and spin up the 53 AI agents.*

4. **Verify the installation:**
   ```bash
   docker ps
   ps aux | grep python
   ```

---

## 🔧 Configuration (`config.yaml`)

Before or after installation, you must configure your environment variables, API keys, and asset inventory.
Edit the file located at: `agents/shared/config.yaml`

**Critical Sections to Edit:**
*   **LLM Provider:** Point it to your local Ollama instance (default is `http://127.0.0.1:11434`).
*   **Asset Inventory:** Define your `critical_hosts` and `critical_subnets`. The Smart Decision Agent (W26) uses this list to decide whether to automatically isolate a machine (e.g., it will block a normal laptop, but will alert humans before blocking a critical Domain Controller).
*   **Passwords & API Keys:** Update the passwords for OpenSearch, Wazuh, MISP, and DFIR-IRIS.

---

## 🛠️ How to Add a New AI Agent

The architecture is built to be highly modular. To create a new agent (e.g., `W48_CustomThreat.py`):

1. **Create the file** in `agents/workers/`.
2. **Inherit from `BaseAgent`**:
   ```python
   from shared.base_agent import BaseAgent
   class CustomThreatAgent(BaseAgent):
       def __init__(self, supervisor_queue):
           super().__init__(name="W48_CustomThreat", ...)
   ```
3. **Implement the 4 core methods:**
   *   `collect()`: Fetch logs from OpenSearch/Wazuh.
   *   `analyze()`: Find anomalies or matches.
   *   `decide()`: Determine severity (INFO, LOW, MEDIUM, HIGH, CRITICAL).
   *   `act()`: Forward to the supervisor or take local action.
4. **Assign it to a Supervisor** (e.g., `soc:detection-supervisor`).
5. **Restart the agents process.**

---

## 🩺 Troubleshooting

*   **High RAM Usage:** If OpenSearch crashes, ensure you have set `vm.max_map_count=262144` on the Linux host (`sudo sysctl -w vm.max_map_count=262144`).
*   **Agents Not Communicating:** Verify that the Redis broker is running (`docker-compose -f compose/core/docker-compose.yml ps`) and that the password in `config.yaml` matches.
*   **LLM Timeouts:** If the Commander agent times out while making decisions, your server might lack the GPU/CPU power for the `llama3` model. Switch `primary_model` to `mistral` or a smaller quantized model in `config.yaml`.

---
*Built with ❤️ for the Cybersecurity Open Source Community.*
