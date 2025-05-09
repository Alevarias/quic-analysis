import torch
import os
import json
from quic_cnn_trainer import QUIC2DCNN

# Model and Data Paths
MODEL_PATH = 'best_model.pth'
TENSOR_PATHS = [
    r'C:\\Users\\aisha\\Downloads\\test_tensor_0.pt',
    r'C:\\Users\\aisha\\Downloads\\test_tensor_1.pt',
    r'C:\\Users\\aisha\\Downloads\\test_tensor_2.pt',
    r'C:\\Users\\aisha\\Downloads\\test_tensor_3.pt'
]

# Load the model
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = QUIC2DCNN(num_classes=9).to(device)
model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
model.eval()

# Class Labels
LABELS = ['amazon', 'chatgpt', 'facebook', 'google', 'instagram', 'linkedin', 'twitter', 'yahoo', 'youtube']

def predict_tensor(tensor_path):
    tensor = torch.load(tensor_path).to(device)
    with torch.no_grad():
        output = model(tensor)
        probabilities = torch.softmax(output, dim=1)
        top_conf, top_idx = torch.max(probabilities, dim=1)
        predicted_label = LABELS[top_idx.item()]
        confidence = top_conf.item()

    print(f"Tensor: {tensor_path}")
    print(f"Predicted: {predicted_label} - Confidence: {confidence:.4f}\n")

if __name__ == "__main__":
    for tensor_path in TENSOR_PATHS:
        if os.path.exists(tensor_path):
            predict_tensor(tensor_path)
        else:
            print(f"Tensor file not found: {tensor_path}")
