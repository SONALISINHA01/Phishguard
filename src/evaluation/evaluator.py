import os
import json
from typing import List, Dict, Any, Tuple
from src.agents.pipeline import PhishGuardPipeline
from src.agents.state import AgentState

class BenchmarkEvaluator:
    """
    Evaluation and Confusion Matrix Engine.
    Executes benchmark test batches, computes classification metrics,
    and generates visual confusion matrices for validation.
    """

    def __init__(self, pipeline: PhishGuardPipeline = None):
        self.pipeline = pipeline or PhishGuardPipeline()

    def evaluate_batch(self, test_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Runs evaluation over a list of test samples.
        Each sample: {"id": str, "sender": str, "subject": str, "body": str, "headers": dict, "ground_truth": "phishing" | "legitimate"}
        """
        tp = 0 # Ground truth phishing, predicted quarantine/flag
        fp = 0 # Ground truth legitimate, predicted quarantine/flag
        tn = 0 # Ground truth legitimate, predicted deliver
        fn = 0 # Ground truth phishing, predicted deliver

        results = []

        for sample in test_samples:
            state: AgentState = self.pipeline.process_email(
                sender=sample.get("sender", ""),
                subject=sample.get("subject", ""),
                body=sample.get("body", ""),
                headers=sample.get("headers", {}),
                email_id=sample.get("id")
            )

            predicted_phish = state.action in ["QUARANTINE", "FLAG"]
            actual_phish = sample.get("ground_truth", "").lower() == "phishing"

            if actual_phish and predicted_phish:
                tp += 1
                outcome = "TP (True Positive)"
            elif not actual_phish and predicted_phish:
                fp += 1
                outcome = "FP (False Positive)"
            elif not actual_phish and not predicted_phish:
                tn += 1
                outcome = "TN (True Negative)"
            else:
                fn += 1
                outcome = "FN (False Negative)"

            results.append({
                "id": state.email_id,
                "sender": state.sender,
                "subject": state.subject,
                "actual": "Phishing" if actual_phish else "Legitimate",
                "predicted": "Phishing/Suspicious" if predicted_phish else "Legitimate",
                "risk_score": state.risk_score,
                "action": state.action,
                "outcome": outcome,
                "explanation": state.explanation
            })

        total = len(test_samples)
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        confusion_matrix = {
            "matrix": [
                [tn, fp],  # Actual Legitimate: [TN, FP]
                [fn, tp]   # Actual Phishing:   [FN, TP]
            ],
            "labels": ["Legitimate (Negative)", "Phishing (Positive)"],
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "total_samples": total
        }

        metrics = {
            "accuracy": round(accuracy * 100, 2),
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1_score * 100, 2),
            "specificity": round(specificity * 100, 2)
        }

        return {
            "metrics": metrics,
            "confusion_matrix": confusion_matrix,
            "detailed_results": results
        }
