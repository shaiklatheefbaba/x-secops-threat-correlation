import hashlib
import time
import json
import os
from datetime import datetime

class ForensicLogger:
    def __init__(self, log_file="xsecops_forensic.chain"):
        self.log_file = log_file
        self.previous_hash = "0" * 64
        
        # Initialize chain if file exists, else start new
        if os.path.exists(self.log_file):
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_entry = json.loads(lines[-1])
                    self.previous_hash = last_entry['current_hash']

    def _calculate_hash(self, data_string):
        """Generates SHA-256 hash of the entry."""
        return hashlib.sha256(data_string.encode()).hexdigest()

    def log_event(self, layer, event_type, details, severity):
        """
        Logs an event with a cryptographic link to the previous entry.
        """
        timestamp = str(datetime.now())
        
        log_entry = {
            "timestamp": timestamp,
            "layer": layer,          # SAST, NIDS, or CORRELATION
            "type": event_type,
            "severity": severity,
            "details": details,
            "previous_hash": self.previous_hash
        }

        # Create a string representation to hash
        log_string = json.dumps(log_entry, sort_keys=True)
        current_hash = self._calculate_hash(log_string)
        
        log_entry['current_hash'] = current_hash
        self.previous_hash = current_hash

        # Write to file (Append mode)
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")
            
        print(f"[{layer}] {event_type.upper()}: {details} (Hash: {current_hash[:8]}...)")

    def verify_integrity(self):
        """
        Forensic Tool: Verifies if the log file has been tampered with.
        """
        print("\n--- Starting Forensic Integrity Check ---")
        if not os.path.exists(self.log_file):
            print("No log file found.")
            return False

        with open(self.log_file, 'r') as f:
            lines = f.readlines()

        prev_hash = "0" * 64
        valid = True
        
        for i, line in enumerate(lines):
            entry = json.loads(line)
            stored_hash = entry['current_hash']
            stored_prev_hash = entry['previous_hash']
            
            # 1. Check Linkage
            if stored_prev_hash != prev_hash:
                print(f"[ALERT] Chain broken at line {i+1}! Data tampering detected.")
                valid = False
                break
            
            # 2. Check Content Integrity (Re-hash the data)
            # Remove the 'current_hash' field to reproduce the original hash input
            entry_copy = entry.copy()
            del entry_copy['current_hash']
            recalculated_hash = self._calculate_hash(json.dumps(entry_copy, sort_keys=True))
            
            if recalculated_hash != stored_hash:
                print(f"[ALERT] Content modified at line {i+1}!")
                valid = False
                break
                
            prev_hash = stored_hash

        if valid:
            print("✅ Forensic Integrity Verified: Chain is intact.")
        else:
            print("❌ Forensic Integrity Failed.")
        return valid