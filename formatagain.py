import pandas as pd
import torch
import json
from collections import defaultdict
import os


def verify_and_load_csv(input_csv):
    """ Verifies the column headers and loads the CSV file. """
    expected_columns = ["size", "timestamp", "directionality", "label"]

    # Read the CSV file
    data = pd.read_csv(input_csv)

    # Verify the columns
    for col in expected_columns:
        if col not in data.columns:
            raise ValueError(f"Missing column: {col}")

    return data


def format_data(row):
    """ Converts JSON arrays to padded tensor """
    max_len = 1000

    # Convert JSON strings to lists
    size = json.loads(row['size'])
    timestamp = json.loads(row['timestamp'])
    directionality = json.loads(row['directionality'])

    # Pad or truncate to max_len
    size = size[:max_len] + [0] * (max_len - len(size))
    timestamp = timestamp[:max_len] + [0] * (max_len - len(timestamp))
    directionality = directionality[:max_len] + [0] * (max_len - len(directionality))

    # Create the tensor
    tensor_data = torch.tensor([size, timestamp, directionality], dtype=torch.float32)
    tensor_data = tensor_data.unsqueeze(0).unsqueeze(0)  # Shape: (1, 1, 3, 1000)

    return tensor_data


def save_tensor(tensor, label, index):
    """ Saves the tensor to a file """
    tensor_path = f"test_tensor_{index}.pt"
    torch.save(tensor, tensor_path)
    print(f"Saved tensor for {label} as {tensor_path}")


def main(input_csv):
    data = verify_and_load_csv(input_csv)

    # Process each row and save tensors
    for idx, row in data.iterrows():
        tensor = format_data(row)
        save_tensor(tensor, row['label'], idx)


if __name__ == "__main__":
    # Example usage
    input_csv = "C:\\Users\\aisha\\Downloads\\aggregated_data.csv"
    main(input_csv)
