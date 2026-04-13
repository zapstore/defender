# Defender

## Overview

Defender is a policy and security service for the Zapstore Nostr relay that controls access to published app events and evaluates their trustworthiness. It acts as a decision layer between event ingestion and persistence, combining fast admission checks with asynchronous analysis to detect spam, scams, and malicious content (WIP).

## Why it exists

As the relay evolved, basic whitelist and blacklist checks became insufficient. Trust decisions now depend on multiple factors: external reputation signals, repository validation, and delayed malware analysis.

Embedding this logic directly into the relay would make it complex, slow, and difficult to extend. Defender exists to separate these concerns, allowing trust and safety rules to evolve independently from the core relay while supporting both immediate decisions and deferred corrective actions.

## Goals

- **Control access to the relay**
  - Apply immediate admission decisions based on whitelist, blacklist, and reputation signals.
  - Support integration with external scoring providers like Vertex.

- **Evaluate published applications**
  - Inspect events representing Android apps and related metadata.
  - Incorporate automated validation sources (e.g., GitHub-based checks).

- **Support asynchronous threat detection**
  - Run slower, deeper analysis such as malware detection and behavioral signals after ingestion.
  - Continuously improve detection using new data sources and heuristics.

- **Enable reactive enforcement**
  - Issue post-publication actions such as revocation or deletion when malicious activity is detected.
  - Maintain consistency between detected threats and relay state.

## Design Principles

- Fast path decisions must be low-latency and resilient to external failures.
- Expensive checks are handled asynchronously and should not block ingestion.
- All decisions must be logged for auditability.
- The system should evolve without requiring changes to the relay core.
