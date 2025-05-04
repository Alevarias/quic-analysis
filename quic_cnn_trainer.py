import pandas as pd
import numpy as np
import json
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset

# Constants
CSV_PATH = "pcap_data.csv"
BATCH_SIZE = 32
LR = 0.001
NUM_EPOCHS = 300
MAX_LEN = 5000
NUM_FEATURES = 3

# Defining the QUIC2DCNN model
class QUIC2DCNN(nn.Module):
    def __init__(self, num_classes: int, num_features: int = 3):
        super(QUIC2DCNN, self).__init__()
        # Convolutional feature extractor
        self.features = nn.Sequential(
            # conv1: cover all features (height=num_features) and small time window
            nn.Conv2d(in_channels=1, out_channels=16, kernel_size=(num_features, 5), padding=(0, 2)),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=(1, 2)),

            # conv2: temporal pattern
            nn.Conv2d(16, 32, kernel_size=(1, 5), padding=(0, 2)),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=(1, 2)),

            # conv3: deeper temporal
            nn.Conv2d(32, 64, kernel_size=(1, 5), padding=(0, 2)),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=(1, 2)),
        )
        # Global pooling to flatten spatial dims
        self.global_pool = nn.AdaptiveAvgPool2d((1, 1))

        # Classifier head
        self.classifier = nn.Sequential(
            nn.Flatten(),                # shape: (batch, 64)
            nn.Linear(64, 128),
            nn.ReLU(inplace=True),
            nn.Dropout(0.5),
            nn.Linear(128, num_classes)  # dynamic output size
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.features(x)
        x = self.global_pool(x)
        x = self.classifier(x)
        return x
    
# Custom Dataset for loading data
class PcapDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.long)
    def __len__(self):
        return len(self.y)
    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

def main():
    print("Processing .csv file")
    df = pd.read_csv(CSV_PATH)
    X_list, y_list = [], []

    # Converting JSON columns to numpy arrays
    for _, row in df.iterrows():
        sizes = np.array(json.loads(row['size']))
        timestamps = np.array(json.loads(row['timestamp']))
        directions = np.array(json.loads(row['directionality']))

        sample = np.stack([sizes, timestamps, directions], axis=0)
        X_list.append(sample)
        y_list.append(row['label'])

    X = np.stack(X_list, axis=0)
    y = LabelEncoder().fit_transform(y_list)

    print("Splitting Dataset into training and testing sets")
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, stratify = y, random_state=42)

    train_ds = PcapDataset(X_train, y_train)
    val_ds = PcapDataset(X_val, y_val)

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE)

    # Setting up the device to use gpu if available
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("Using device:", torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU")    
    
    # Initializing the model, loss function and optimizer
    num_classes = len(np.unique(y))
    model = QUIC2DCNN(num_classes=num_classes, num_features=NUM_FEATURES).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=LR)

    # Initializing variable to track best validation accuracy
    best_val_acc = 0.0

    # Training loop
    for epoch in range(1, NUM_EPOCHS+1):
        model.train()
        train_loss = 0.0
        correct = 0
        total = 0
        for Xb, yb in train_loader:
            Xb, yb = Xb.to(device), yb.to(device)
            optimizer.zero_grad()
            logits = model(Xb.unsqueeze(1))
            loss = criterion(logits, yb)
            loss.backward()
            optimizer.step()

            train_loss += loss.item() * Xb.size(0)
            preds = logits.argmax(dim=1)
            correct += (preds == yb).sum().item()
            total += yb.size(0)

        train_loss /= total
        train_acc = correct / total

        # Switching to evaluation mode to text accuracy
        model.eval()
        val_loss = 0.0
        correct = 0
        total = 0

        # Validation loop
        with torch.no_grad():
            for Xb, yb in val_loader:
                Xb, yb = Xb.to(device), yb.to(device)
                logits = model(Xb.unsqueeze(1))
                loss = criterion(logits, yb)

                val_loss += loss.item() * Xb.size(0)
                preds = logits.argmax(dim=1)
                correct += (preds == yb).sum().item()
                total += yb.size(0)
        val_loss /= total
        val_acc = correct / total

        print(f"Epoch {epoch}/{NUM_EPOCHS} - "
              f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f} - "
              f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}")
        
        # Saves the model if validation accuracy improves
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save(model.state_dict(), f"best_model_{epoch}.pth")
            torch.save(model.state_dict(), "best_model.pth")
            print("Saved new best model")

        # elif epoch % 5 == 0:
        #     torch.save(model.state_dict(), f"model_epoch_{epoch}.pth")
        #     print(f"Saved model at epoch {epoch}")

    print("Training complete. Best validation accuracy: {:.4f}".format(best_val_acc))

if __name__ == "__main__":
    main()