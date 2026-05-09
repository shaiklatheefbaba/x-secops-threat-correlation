import pandas as pd
import numpy as np
import shap
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

class NIDSEngine:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        self.explainer = None
        self.feature_names = None

    def train_simulation(self):
        """
        Trains on synthetic data for prototype purposes.
        Replace with CIC-IDS2017 loader for final research.
        """
        print("Training NIDS on Synthetic Data (Prototype Mode)...")
        
        # Generate synthetic data mimicking web traffic
        # Features: Duration, SrcBytes, DstBytes, FailedLogins, RootAccess, HttpRequests, SqlKeywords
        n_samples = 2000
        X = np.random.rand(n_samples, 7)
        # Inject patterns: High SQL keywords + High DstBytes = SQL Injection Attack
        X[:100, 6] = X[:100, 6] * 10 # High SQL keywords
        y = np.zeros(n_samples)
        y[:100] = 1 # Mark as attack
        
        self.feature_names = ['Duration', 'SrcBytes', 'DstBytes', 'FailedLogins', 'RootAccess', 'HttpRequests', 'SqlKeywords']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
        self.model.fit(X_train, y_train)
        
        print("NIDS Training Complete. Accuracy: {:.2f}".format(self.model.score(X_test, y_test)))
        
        # Initialize SHAP explainer
        self.explainer = shap.TreeExplainer(self.model)

    def analyze_packet(self, packet_features):
        """
        packet_features: list of values corresponding to feature_names
        """
        # Reshape for single prediction
        data = np.array(packet_features).reshape(1, -1)
        prediction = self.model.predict(data)[0]
        prob = self.model.predict_proba(data)[0][1]
        
        return prediction, prob, data

    def explain_decision(self, data_instance):
        """
        Returns SHAP values to explain why the packet was flagged.
        """
        shap_values = self.explainer.shap_values(data_instance)
        
        # For binary classification, shap_values is a list of arrays. 
        # Index 1 usually corresponds to the positive class (Attack).
        vals = shap_values[1] if isinstance(shap_values, list) else shap_values
        
        explanation = {}
        for name, val in zip(self.feature_names, vals[0]):
            explanation[name] = val
            
        return explanation

    def plot_explanation(self, data_instance, save_path="shap_plot.png"):
        """Generates a SHAP force plot or summary plot."""
        shap_values = self.explainer.shap_values(data_instance)
        # Note: Saving SHAP plots requires matplotlib
        plt.figure()
        shap.summary_plot(shap_values, data_instance, feature_names=self.feature_names, show=False)
        plt.savefig(save_path)
        plt.close()