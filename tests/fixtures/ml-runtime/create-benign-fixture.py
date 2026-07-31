import pickle
import sys

# Benign model - just a simple dictionary
model_data = {
    'type': 'test_model',
    'version': '1.0',
    'weights': [0.1, 0.2, 0.3],
}

with open('tests/fixtures/ml-runtime/benign/model.pkl', 'wb') as f:
    pickle.dump(model_data, f)

print("✓ Created benign model fixture")
