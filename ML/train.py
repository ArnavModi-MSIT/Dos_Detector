#!/usr/bin/env python3
"""
Combined Layer-Based Attack Detection Model Trainer
---------------------------------------------------
This script trains separate models for each OSI layer (Network, Internet, Transport, Application)
and combines them into one `.pkl` file using Gradient Boosting for improved accuracy.

"""

import pandas as pd
import joblib
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score


def train_model(df, label_column, drop_columns, name, encode_labels=True):
    """
    Trains a Gradient Boosting model on the given DataFrame.

    Parameters:
        df (DataFrame): Input dataset.
        label_column (str): The column name to be used as the target.
        drop_columns (list): Columns to drop from the dataset before training.
        name (str): Name of the layer for display/logging.
        encode_labels (bool): Whether to encode labels using LabelEncoder.

    Returns:
        model: Trained classifier.
        encoder: LabelEncoder used for label_column (None if not used).
    """
    print(f"\n📊 Training: {name}")
    
    # Drop unnecessary columns
    df = df.drop(columns=drop_columns)

    encoder = None
    # Encode target column if it's categorical
    if encode_labels:
        if df[label_column].dtype == "object":
            df[label_column] = df[label_column].str.lower()
        encoder = LabelEncoder()
        df[label_column] = encoder.fit_transform(df[label_column])

    # Split data into features and labels
    X = df.drop(columns=[label_column])
    y = df[label_column]

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Initialize and train Gradient Boosting model
    model = GradientBoostingClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate the model
    y_pred = model.predict(X_test)
    print("🎯 Classification Report:\n")
    print(classification_report(y_test, y_pred, target_names=encoder.classes_ if encoder else None))
    print(f"✅ Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    
    return model, encoder


def main():
    """
    Main training workflow.
    Trains separate models for each layer and stores them in a single dictionary.
    Saves the dictionary as `combined_rf_model.pkl`.
    """
    combined_model = {}

    # 1️⃣ Train model for Network Layer attacks (e.g., ARP spoofing, MAC flooding)
    try:
        df_net = pd.read_csv("network_layer_attacks.csv")
        model, encoder = train_model(
            df=df_net,
            label_column="attack_type",
            drop_columns=["timestamp", "src_mac", "dst_mac"],
            name="Network Layer"
        )
        combined_model["network"] = {"model": model, "encoder": encoder}
    except Exception as e:
        print("❌ Network layer error:", e)

    # 2️⃣ Train model for Internet Layer attacks (e.g., IP spoofing, UDP flood)
    try:
        df_inet = pd.read_csv("internet_layer_attacks.csv")

        # Combine multiple binary attack types into a single label
        df_inet["is_attack"] = df_inet[["ip_spoofing", "ping_flood", "udp_flood"]].sum(axis=1).apply(lambda x: 1 if x > 0 else 0)
        df_inet = df_inet.drop(columns=["ip_spoofing", "ping_flood", "udp_flood"])

        # Encode 'protocol' field (e.g., TCP, UDP) into numeric values
        proto_encoder = LabelEncoder()
        df_inet["protocol"] = proto_encoder.fit_transform(df_inet["protocol"])

        model, encoder = train_model(
            df=df_inet,
            label_column="is_attack",
            drop_columns=["timestamp", "src_mac", "src_ip", "dst_ip"],
            name="Internet Layer",
            encode_labels=False  # Already numeric
        )
        combined_model["internet"] = {
            "model": model,
            "encoder": encoder,
            "protocol_encoder": proto_encoder
        }
    except Exception as e:
        print("❌ Internet layer error:", e)

    # 3️⃣ Train model for Transport Layer attacks (e.g., SYN flood)
    try:
        df_trans = pd.read_csv("transport_layer_attacks.csv")
        model, encoder = train_model(
            df=df_trans,
            label_column="flag_label",
            drop_columns=["timestamp", "src_ip", "dst_ip"],
            name="Transport Layer"
        )
        combined_model["transport"] = {"model": model, "encoder": encoder}
    except Exception as e:
        print("❌ Transport layer error:", e)

    # 4️⃣ Train model for Application Layer attacks (e.g., HTTP flood, DNS tunneling)
    try:
        df_app = pd.read_csv("application_layer_attacks.csv")
        model, encoder = train_model(
            df=df_app,
            label_column="attack_label",
            drop_columns=["timestamp", "src_ip"],
            name="Application Layer"
        )
        combined_model["application"] = {"model": model, "encoder": encoder}
    except Exception as e:
        print("❌ Application layer error:", e)

    # 💾 Save all trained models + encoders into a single .pkl file
    joblib.dump(combined_model, "combined_rf_model.pkl")
    print("\n✅ All models and encoders saved in `combined_rf_model.pkl` ✅")


if __name__ == "__main__":
    print("🚀 Starting training for all layers...")
    main()
