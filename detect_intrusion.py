import pandas as pd
import numpy as np
import joblib
import time
import logging
from datetime import datetime
import os
import sys
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
# =========================================
# CONFIGURATION
# =========================================
MODEL_PATH = 'ids_random_forest_model.pkl'
DATA_PATH = 'simulated_traffic.csv'
LOG_FILE = 'ids_detections.log'
BENIGN_LABEL = 'Normal Traffic' # Change this if your safe label is different

# =========================================
# 1. SYSTEM SETUP (Logging & Loading)
# =========================================
# Setup Logging: specific format for SOC compliance
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def print_banner():
    print("\n" + "="*50)
    print("   🛡️  IDS REAL-TIME DETECTION MODULE STARTED  🛡️")
    print("="*50)
    print(f"[*] Loading Model from: {MODEL_PATH}")
    print(f"[*] Loading Traffic Stream from: {DATA_PATH}")
    print(f"[*] Logging to: {LOG_FILE}\n")

# =========================================
# 2. CORE FUNCTIONS
# =========================================
def load_resources():
    try:
        model = joblib.load(MODEL_PATH)
        
        # Load data
        data = pd.read_csv(DATA_PATH)
        
        # --- FIX IS HERE: CLEAN THE COLUMN NAMES ---
        # This removes all leading/trailing spaces from column names
        data.columns = data.columns.str.strip()
        # -------------------------------------------

        # labels = data['Actual_Label'] # (Optional)
        features = data.drop('Actual_Label', axis=1)
        
        print("[+] Model and Data loaded successfully.")
        return model, features
    except FileNotFoundError as e:
        print(f"[-] ERROR: Missing file. {e}")
        sys.exit(1)

def determine_severity(confidence, prediction):
    """
    Step 6: Incident Response Logic
    """
    if prediction == BENIGN_LABEL:
        return "LOW"
    
    if confidence > 0.90:
        return "CRITICAL"
    elif confidence > 0.70:
        return "HIGH"
    else:
        return "MEDIUM"

def automated_response(severity, prediction, src_ip="192.168.1.X"):
    """
    Simulates the action taken by the firewall/SOAR
    """
    if severity == "CRITICAL":
        return f"BLOCK IP {src_ip} (Firewall Rule #992)"
    elif severity == "HIGH":
        return "Ticket Created (Tier 2 Analyst)"
    elif severity == "MEDIUM":
        return "Logged for Hunting"
    return "Allow"

# =========================================
# 3. MAIN EXECUTION LOOP
# =========================================
def run_detection_engine():
    model, traffic_stream = load_resources()
    print("[*] Starting Traffic Analysis Loop... (Press Ctrl+C to Stop)\n")
    
    # Define key features to watch (based on your Feature Importance analysis)
    # Note: Ensure these match your CSV column names exactly
    # In run_detection_engine function:
    key_features = ['Bwd Packet Length Std', 'Destination Port', 'Flow Duration'] 
    # (Notice I removed the spaces inside the quotes)
    
    try:
        for index, row in traffic_stream.iterrows():
            
            # 1. Preprocessing
            packet_data = row.values.reshape(1, -1)
            
            # 2. Prediction
            prediction = model.predict(packet_data)[0]
            confidence = np.max(model.predict_proba(packet_data))
            
            # 3. Severity & Response
            severity = determine_severity(confidence, prediction)
            response = automated_response(severity, prediction)
            
            # 4. Console Output
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if prediction != BENIGN_LABEL:
                # --- NEW: EXTRACT EVIDENCE ---
                # We grab the actual values from the row to show "Why"
                # We use .get() to avoid crashing if column names have slight spelling diffs
                evidence = []
                for feat in key_features:
                    val = row.get(feat, "N/A") 
                    evidence.append(f"{feat.strip()}: {val}")
                
                evidence_str = " | ".join(evidence)
                # -----------------------------

                alert_msg = (
                    f"⚠️  [ALERT] {prediction.upper()} DETECTED\n"
                    f"    Conf: {confidence*100:.1f}% | Sev: {severity}\n"
                    f"    🔍 Evidence: {evidence_str}\n"  # <--- Added Line
                    f"    🛡️  Action: {response}"
                )
                print(f"\033[91m{timestamp} | {alert_msg}\033[0m") 
                
                logging.warning(f"INTRUSION DETECTED: Type={prediction}, Conf={confidence:.4f}, Evidence=[{evidence_str}]")
            
            else:
                pass 

            time.sleep(0.5) 

    except KeyboardInterrupt:
        print("\n\n[!] User Stopped Detection.")

if __name__ == "__main__":
    print_banner()
    run_detection_engine()