#!/usr/bin/env python3

"""
Multi-Layer Network Attack Classifier Trainer
============================================

Trains Random Forest classifiers to detect attacks at different network layers:
1. Network Layer (MAC/Datalink)
2. Internet Layer (IP)
3. Transport Layer (TCP/UDP)
4. Application Layer

For each layer:
- Loads the training dataset
- Preprocesses features
- Trains a Random Forest classifier
- Evaluates performance
- Saves the trained models with their encoders

Output: Single .pkl file containing all models and encoders
"""

import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score


def train_model(df, label_column, drop_columns, name, encode_labels=True):
    """
    Train a Random Forest classifier on network data
    
    Parameters:
    - df: DataFrame containing features and labels
    - label_column: Name of the target variable column
    - drop_columns: Columns to remove before training
    - name: Display name for this model
    - encode_labels: Whether to encode string labels (default: True)
    
    Returns:
    - Trained model
    - Label encoder (if used)
    """
    print(f"\n📊 Training: {name}")
    
    # Remove unnecessary columns
    df = df.drop(columns=drop_columns)

    # Encode string labels to numeric values if needed
    encoder = None
    if encode_labels:
        if df[label_column].dtype == "object":
            df[label_column] = df[label_column].str.lower()  # Normalize case
        encoder = LabelEncoder()
        df[label_column] = encoder.fit_transform(df[label_column])

    # Split into features (X) and target (y)
    X = df.drop(columns=[label_column])
    y = df[label_column]

    # Create train/test splits (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, 
        test_size=0.2, 
        random_state=42  # Fixed seed for reproducibility
    )

    # Initialize and train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,  # Number of decision trees
        random_state=42    # Fixed seed
    )
    model.fit(X_train, y_train)

    # Evaluate model performance
    y_pred = model.predict(X_test)
    print("🎯 Classification Report:\n")
    print(classification_report(
        y_test, 
        y_pred, 
        target_names=encoder.classes_ if encoder else None
    ))
    print(f"✅ Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    
    return model, encoder


def main():
    """Main training pipeline for all network layers"""
    # Dictionary to store all trained models and encoders
    combined_model = {}

    # 1️⃣ Network Layer (MAC/Datalink) Training
    try:
        print("\n" + "="*50)
        print("🛜 Training Network Layer Model")
        print("="*50)
        
        df_net = pd.read_csv("network_layer_attacks.csv")
        model, encoder = train_model(
            df=df_net,
            label_column="attack_type",
            drop_columns=["timestamp", "src_mac", "dst_mac"],  # Remove non-features
            name="Network Layer"
        )
        combined_model["network"] = {
            "model": model, 
            "encoder": encoder
        }
    except Exception as e:
        print("❌ Network layer error:", e)

    # 2️⃣ Internet Layer (IP) Training
    try:
        print("\n" + "="*50)
        print("🌐 Training Internet Layer Model")
        print("="*50)
        
        df_inet = pd.read_csv("internet_layer_attacks.csv")
        
        # Combine multiple attack flags into single binary label
        df_inet["is_attack"] = df_inet[["ip_spoofing", "ping_flood", "udp_flood"]].sum(axis=1)
        df_inet["is_attack"] = df_inet["is_attack"].apply(lambda x: 1 if x > 0 else 0)
        df_inet = df_inet.drop(columns=["ip_spoofing", "ping_flood", "udp_flood"])

        # Encode protocol strings (tcp/udp/icmp etc.)
        proto_encoder = LabelEncoder()
        df_inet["protocol"] = proto_encoder.fit_transform(df_inet["protocol"])

        model, encoder = train_model(
            df=df_inet,
            label_column="is_attack",
            drop_columns=["timestamp", "src_mac", "src_ip", "dst_ip"],
            name="Internet Layer",
            encode_labels=False  # is_attack is already 0/1
        )
        combined_model["internet"] = {
            "model": model,
            "encoder": encoder,
            "protocol_encoder": proto_encoder
        }
    except Exception as e:
        print("❌ Internet layer error:", e)

    # 3️⃣ Transport Layer (TCP/UDP) Training
    try:
        print("\n" + "="*50)
        print("🚦 Training Transport Layer Model")
        print("="*50)
        
        df_trans = pd.read_csv("transport_layer_attacks.csv")
        model, encoder = train_model(
            df=df_trans,
            label_column="flag_label",  # TCP flag patterns
            drop_columns=["timestamp", "src_ip", "dst_ip"],
            name="Transport Layer"
        )
        combined_model["transport"] = {
            "model": model, 
            "encoder": encoder
        }
    except Exception as e:
        print("❌ Transport layer error:", e)

    # 4️⃣ Application Layer Training
    try:
        print("\n" + "="*50)
        print("📱 Training Application Layer Model")
        print("="*50)
        
        df_app = pd.read_csv("application_layer_attacks.csv")
        model, encoder = train_model(
            df=df_app,
            label_column="attack_label",  # HTTP/DNS attacks etc.
            drop_columns=["timestamp", "src_ip"],
            name="Application Layer"
        )
        combined_model["application"] = {
            "model": model, 
            "encoder": encoder
        }
    except Exception as e:
        print("❌ Application layer error:", e)

    # 🔐 Save all models and encoders to single file
    joblib.dump(combined_model, "combined_rf_model.pkl")
    print("\n✅ All models and encoders saved in `combined_rf_model.pkl` ✅")


if __name__ == "__main__":
    print("🚀 Starting training for all layers...")
    main()
