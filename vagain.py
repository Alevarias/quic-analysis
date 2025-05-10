import json
from collections import defaultdict


class TrafficValidator:
    def __init__(self, ground_truth_app=None, min_confidence=95.0):
        """
        Initialize with ground truth (actual app name) and confidence threshold.

        Args:
            ground_truth_app (str): Actual app name (e.g., "twitter").
            min_confidence (float): Minimum confidence % to accept prediction (default: 95.0).
        """
        self.ground_truth = ground_truth_app.lower() if ground_truth_app else None
        self.min_confidence = min_confidence
        self.predictions = []

    def add_prediction(self, predicted_app, confidence, ports_used=None):
        """
        Store a prediction for validation.

        Args:
            predicted_app (str): Predicted app (e.g., "twitter").
            confidence (float): Confidence percentage (e.g., 98.14).
            ports_used (list): List of observed ports (e.g., [443, 80]).
        """
        self.predictions.append({
            "predicted_app": predicted_app.lower(),
            "confidence": confidence,
            "ports_used": ports_used or []
        })

    def validate(self, index=-1):
        """
        Validate the latest (or specific) prediction against ground truth.

        Args:
            index (int): Index of prediction to validate (default: -1 for latest).

        Returns:
            tuple: (is_correct (bool), message (str))
        """
        if not self.predictions:
            return False, "No predictions available."

        pred = self.predictions[index]
        is_match = pred["predicted_app"] == self.ground_truth
        meets_confidence = pred["confidence"] >= self.min_confidence

        if not meets_confidence:
            return False, "Low confidence (" + str(pred["confidence"]) + "% < " + str(self.min_confidence) + "%)"
        elif not is_match:
            return (False,
                    "Incorrect prediction (got: " + pred["predicted_app"] + ", expected: " + self.ground_truth + ")")
        else:
            return True, "Correct prediction (" + str(pred["confidence"]) + "% confidence)"

    def save_to_json(self, filename="predictions.json"):
        """Save all predictions to a JSON file."""
        with open(filename, "w") as f:
            json.dump(self.predictions, f, indent=2)

    @staticmethod
    def load_from_json(filename="predictions.json"):
        """Load predictions from a JSON file."""
        with open(filename, "r") as f:
            data = json.load(f)
        validator = TrafficValidator()
        validator.predictions = data
        return validator


# Example Usage
if __name__ == "__main__":
    # Initialize validator (set ground truth if known)
    validator = TrafficValidator(ground_truth_app="twitter")

    # Add a prediction (e.g., from your analysis)
    validator.add_prediction(
        predicted_app="twitter",
        confidence=98.14,
        ports_used=[443, 61005]
    )

    # Validate
    is_correct, message = validator.validate()
    print(message)  # Output: "Correct prediction (98.14% confidence)"

    # Save predictions to JSON
    validator.save_to_json()