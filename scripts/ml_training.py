from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pandas as pd
from urllib.parse import urlparse
import joblib
import os

# Function to extract features from a URL
def extract_features(url):
    parsed = urlparse(url.strip().lower())
    domain = parsed.netloc
    url_length = len(url)
    has_https = 1 if url.startswith("https") else 0
    tld = domain.split(".")[-1] if "." in domain else ""
    suspicious_tlds = ["xyz", "tk", "ml", "info", "ru"]
    tld_suspicious = 1 if tld in suspicious_tlds else 0

    return {
        "url_length": url_length,
        "has_https": has_https,
        "tld_suspicious": tld_suspicious
    }

# Function to train the model
def train_model():
    # Dataset of URLs
    data = pd.DataFrame({
        "url": [
            "http://example.com",  # Safe
            "https://securebank.com",  # Safe
            "http://phishing-site.xyz",  # Malicious
            "http://malicious.tk",  # Malicious
            "https://fake-login.info",  # Malicious
            "http://safe-site.org",  # Safe
            "https://shopping-site.com",  # Safe
            "http://scam-site.ru",  # Malicious
            "http://credit-card-fraud.ml",  # Malicious
            "https://safe-travel.com",  # Safe
            "http://malicious-login.tk",  # Malicious
            "https://secure-payment.com",  # Safe
            "http://phishing-email.xyz",  # Malicious
            "http://bad-site.tk",  # Malicious
            "https://trusted-site.com",  # Safe
            "http://data-leak.ml",  # Malicious
            "http://fake-update.info",  # Malicious
            "https://legit-shop.org",  # Safe
            "http://malware-download.tk",  # Malicious
            "http://stealing-data.ru",  # Malicious
        ],
        "is_malicious": [
            0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 
            1, 0, 1, 1, 0, 1, 1, 0, 1, 1
        ]
    })

    # Extract features for each URL
    feature_data = pd.DataFrame([extract_features(url) for url in data["url"]])
    feature_data["is_malicious"] = data["is_malicious"]

    # Split the data into training and testing sets
    X = feature_data.drop("is_malicious", axis=1)
    y = feature_data["is_malicious"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train the Random Forest model
    model = RandomForestClassifier(random_state=42)
    model.fit(X_train, y_train)

    # Evaluate the model
    y_pred = model.predict(X_test)
    print("Model Accuracy:", accuracy_score(y_test, y_pred))
    print("Classification Report:\n", classification_report(y_test, y_pred))

    # Save the trained model
    save_model(model, "ml_model.pkl")

    return model

# Function to save the trained model
def save_model(model, filename):
    if not os.path.exists("models"):
        os.makedirs("models")
    filepath = os.path.join("models", filename)
    joblib.dump(model, filepath)
    print(f"Model saved to {filepath}")

# Function to load the trained model
def load_model(filename):
    filepath = os.path.join("models", filename)
    if os.path.exists(filepath):
        model = joblib.load(filepath)
        print(f"Model loaded from {filepath}")
        return model
    else:
        print("Model file not found. Train the model first.")
        return None

# Predict if a URL is malicious
def predict_url(url, model):
    features = pd.DataFrame([extract_features(url)])
    prediction = model.predict(features)[0]
    return "Malicious" if prediction == 1 else "Safe"

if __name__ == "__main__":
    # Train and save the model
    model = train_model()

    # Load the trained model
    model = load_model("ml_model.pkl")

    # Predict new URLs
    if model:
        test_urls = [
            "https://phishing-site.xyz",
            "http://securebank.com",
            "http://malware-download.tk",
            "https://trusted-site.com",
            "http://fake-update.info"
        ]
        for url in test_urls:
            result = predict_url(url, model)
            print(f"The URL '{url}' is classified as: {result}")
