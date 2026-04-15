# test_model.py
import pickle
import pandas as pd

# Load model and scaler
with open('models/isolation_forest.pkl', 'rb') as f:
    model = pickle.load(f)
with open('models/scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

print("Model loaded successfully.")
print(f"Model type: {type(model)}")
print(f"Number of estimators: {model.n_estimators}")
