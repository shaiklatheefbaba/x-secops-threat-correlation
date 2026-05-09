import time
from immutable_logger import ForensicLogger
from sast_engine import SASTEngine
from NIDS_Engine import NIDSEngine

def main():
    # 1. Initialize Components
    logger = ForensicLogger()
    logger.log_event("SYSTEM", "STARTUP", "Initializing X-SecOps Framework", "INFO")
    
    sast = SASTEngine()
    nids = NIDSEngine()
    
    # 2. Train/Load NIDS
    nids.train_simulation()
    
    # 3. Phase 1: Static Analysis (Pre-deployment scan)
    print("\n--- Phase 1: Static Code Analysis ---")
    # Mock vulnerable code for demonstration
    vulnerable_code = """
    def get_user(user_id):
        # Vulnerable SQL query construction
        query = "SELECT * FROM users WHERE id = " + user_id
        execute(query)
    """
    
    is_vuln, conf = sast.scan_code(vulnerable_code)
    
    context_alert = False
    if is_vuln:
        msg = f"Vulnerability Detected in module 'user_auth'. Confidence: {conf:.2f}"
        logger.log_event("SAST", "VULN_DETECT", msg, "HIGH")
        print(f"⚠️  SAST Alert: {msg}")
        context_alert = True # Set a flag to heighten NIDS sensitivity
    
    # 4. Phase 2: Runtime Monitoring (Simulated Traffic)
    print("\n--- Phase 2: Runtime Network Monitoring ---")
    
    # Simulating a normal packet
    packet_normal = [0.1, 500, 500, 0, 0, 10, 0.1] 
    pred, prob, _ = nids.analyze_packet(packet_normal)
    if pred == 0:
        print("Packet 1: Normal Traffic")
        
    # Simulating an Attack Packet (High SQL Keywords)
    # If SAST found a SQLi vuln earlier, we treat this more seriously
    packet_attack = [0.5, 200, 1000, 1, 0, 50, 0.9] # High 'SqlKeywords' value
    pred, prob, data_instance = nids.analyze_packet(packet_attack)
    
    if pred == 1 or (prob > 0.4 and context_alert):
        print(f"🚨 NIDS Alert: Suspicious Traffic Detected! Probability: {prob:.2f}")
        
        # 5. Phase 3: Explainable AI & Correlation
        print("\n--- Phase 3: XAI & Correlation ---")
        explanation = nids.explain_decision(data_instance)
        
        # Sort features by impact
        top_factors = sorted(explanation.items(), key=lambda x: abs(x[1]), reverse=True)[:3]
        explanation_str = f"Top factors: {top_factors}"
        
        # Correlation Logic
        correlation_msg = f"NIDS detected attack driven by {top_factors[0][0]}. "
        if context_alert and "SqlKeywords" in str(top_factors):
            correlation_msg += "CORRELATED: Matches known Source Code SQL Vulnerability!"
            severity = "CRITICAL"
        else:
            severity = "HIGH"
            
        logger.log_event("CORRELATION", "THREAT_CORRELATION", correlation_msg, severity)
        logger.log_event("XAI", "EXPLANATION", explanation_str, "INFO")
        
        print(f"Explanation: {explanation_str}")
        print(f"Final Verdict: {correlation_msg}")
        
        # Generate Plot
        nids.plot_explanation(data_instance)
        print("Generated SHAP explanation plot: shap_plot.png")

    # 6. Verify Logs
    logger.verify_integrity()

if __name__ == "__main__":
    main()