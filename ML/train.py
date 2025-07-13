#!/usr/bin/env python3

import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
from sklearn.ensemble import GradientBoostingClassifier

def train_model(df, label_column, drop_columns, name, encode_labels=True):
    print(f"\n📊 Training: {name}")
    df = df.drop(columns=drop_columns)

    encoder = None
    if encode_labels:
        if df[label_column].dtype == "object":
            df[label_column] = df[label_column].str.lower()
        encoder = LabelEncoder()
        df[label_column] = encoder.fit_transform(df[label_column])

    X = df.drop(columns=[label_column])
    y = df[label_column]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = GradientBoostingClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("🎯 Classification Report:\n")
    print(classification_report(y_test, y_pred, target_names=encoder.classes_ if encoder else None))
    print(f"✅ Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    
    return model, encoder


def main():
    combined_model = {}

    # 1️⃣ Network Layer
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

    # 2️⃣ Internet Layer
    try:
        df_inet = pd.read_csv("internet_layer_attacks.csv")
        df_inet["is_attack"] = df_inet[["ip_spoofing", "ping_flood", "udp_flood"]].sum(axis=1).apply(lambda x: 1 if x > 0 else 0)
        df_inet = df_inet.drop(columns=["ip_spoofing", "ping_flood", "udp_flood"])

        # Encode 'protocol'
        proto_encoder = LabelEncoder()
        df_inet["protocol"] = proto_encoder.fit_transform(df_inet["protocol"])

        model, encoder = train_model(
            df=df_inet,
            label_column="is_attack",
            drop_columns=["timestamp", "src_mac", "src_ip", "dst_ip"],
            name="Internet Layer",
            encode_labels=False  # is_attack is already numeric
        )
        combined_model["internet"] = {
            "model": model,
            "encoder": encoder,
            "protocol_encoder": proto_encoder
        }
    except Exception as e:
        print("❌ Internet layer error:", e)

    # 3️⃣ Transport Layer
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

    # 4️⃣ Application Layer
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

    # 🔐 Save everything in 1 file
    joblib.dump(combined_model, "combined_rf_model.pkl")
    print("\n✅ All models and encoders saved in `combined_rf_model.pkl` ✅")


if __name__ == "__main__":
    print("🚀 Starting training for all layers...")
    main()
