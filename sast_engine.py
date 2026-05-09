import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import os

class SASTEngine:
    def __init__(self):
        print("Loading CodeBERT SAST Model...")
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Running SAST on: {self.device}")
        
        # Using a model fine-tuned for vulnerability detection (smaller version for 1650)
        model_name = "mrm8488/codebert-base-finetuned-detect-insecure-code"
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name).to(self.device)

    def scan_code(self, code_snippet):
        """
        Analyzes a code snippet for vulnerabilities.
        Returns: Is_Vulnerable (bool), Confidence (float)
        """
        inputs = self.tokenizer(code_snippet, return_tensors="pt", truncation=True, max_length=512).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        
        # Assume label 1 is insecure (check model specifics usually 0=safe, 1=unsafe)
        confidence = probs[0][1].item()
        is_vulnerable = confidence > 0.5
        
        return is_vulnerable, confidence

    def analyze_file(self, file_path):
        if not os.path.exists(file_path):
            return []
        
        with open(file_path, 'r') as f:
            content = f.read()
            
        # In a real app, you'd split by functions. 
        # For prototype, we scan the whole block or chunks.
        vuln, conf = self.scan_code(content)
        
        findings = []
        if vuln:
            findings.append({
                "file": file_path,
                "type": "CodeBERT_Detected_Vulnerability",
                "confidence": conf,
                "snippet": content[:50] + "..." # Log start of file
            })
        return findings