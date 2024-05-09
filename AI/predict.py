import time
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import load_model
from pymongo import MongoClient

def process_real_time_data():
    # Connect to the MongoDB database
    client = MongoClient('mongodb://192.168.160.130:27017/')
    db = client['deeplearning_db']
    input_collection = db['valid_csv']
    output_collection = db['predictions']  # Create a new collection for storing predictions

    while True:
        # Retrieve the data from the MongoDB collection
        data = list(input_collection.find({}, {'_id': 0}))

        # Check if there is data to process
        if data:
            # Convert the data to a Pandas DataFrame
            df = pd.DataFrame(data)

            # Standardize the features (using the same scaler as in the training script)
            scaler = StandardScaler()
            X_test = scaler.fit_transform(df)

            # Load the saved model
            loaded_model = load_model('trained_model_final.keras')

            # Make predictions
            predictions = loaded_model.predict(X_test)
            rounded_predictions = np.round(predictions)

            # Print or use the predictions as needed
            print("Predictions:")
            print(rounded_predictions)

            # Store the predictions in the new MongoDB collection
            output_collection.insert_many([{'prediction': int(pred)} for pred in rounded_predictions.flatten()])
            print("Predictions stored in the MongoDB collection.")

            # Clear the input MongoDB collection
            input_collection.delete_many({})
            print("Input MongoDB collection cleared.")

        else:
            print("No data found in the MongoDB collection. Waiting for new data...")

        # Wait for a certain amount of time before checking again
        time.sleep(1)  # Wait for 1 minute (adjust as needed)

if __name__ == "__main__":
    process_real_time_data()
