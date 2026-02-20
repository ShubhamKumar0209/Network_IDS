# Network_IDS

**OVERVIEW**

This project implements a lightweight, real-time Network Intrusion Detection System (NIDS) powered by Machine Learning.
Unlike traditional signature-based firewalls, this system detects malicious traffic using behavioral patterns extracted from network flows.

The model identifies:
DDoS Attacks
Brute Force Attacks
Botnet Activity

Additionally, it includes an Automated Incident Response Module that simulates defensive actions (Block / Alert / Allow) based on threat severity and model confidence.

**Key Achievements**
1. 99.85% Accuracy, macro F1-score of 0.97
2. Inference Time: ~0.02 seconds per packet
3. High precision for DDoS and Brute Force detection
4. Automated Severity-Based Response Logic

**System Architecture**
This project follows a Hybrid Cloud-Edge Architecture:

1. Training Environment (Google Colab)
2. Large dataset processing
3. Random Forest model training
4. Model serialization (.pkl)

**Deployment Environment (Local Machine)**
1. Real-time inference using detect_intrusion.py
2. Simulated live traffic input
3. Automated response logic

**Dataset**
Source: CIC-IDS (Canadian Institute for Cybersecurity)
1. ~1,048,575 network flow records
2. 52 behavioral features
3. Focus on statistical packet behavior (not payload inspection)

Key engineering optimizations:
1. Removed NaN and Infinity values
2. Used Stratified Sampling (20%) to maintain class balance
3. Applied Label Encoding for categorical features

**Model Details**
Algorithm: Random Forest Classifier
Why Random Forest?
1. Excellent performance on structured tabular data
2. Fast inference
3. Feature importance explainability
4. Lower computational cost compared to Deep Learning

**Hyperparameters**
1. n_estimators = 50
2. max_depth = 15
3. n_jobs = -1 (parallel processing)

**Feature Insight**
The most critical indicators of compromise were:
1. Packet Length Variance
2. Packet Length Standard Deviation

Insight:
Attack tools often generate packets of identical size (low variance), while legitimate human traffic shows natural variation.
