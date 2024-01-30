#import libraries
import csv
import os

import numpy as np
import pandas as pd

#paths to files
feature_of_counts_temp = "./data/processed_data/feature_vectors_counts_temp.csv"
feature_of_counts = "./data/processed_data/feature_vectors_counts.csv"
dir_of_files = "./data/raw_data/feature_vectors/"
known_malware_files = "./data/raw_data/sha256_family.csv"


#functions used

def count_feature_set(lines):
    FEATURES_SET = {
        "feature": 1,
        "permission": 2,
        "activity": 3,
        "service_receiver": 3,
        "provider": 3,
        "service": 3,
        "intent": 4,
        "api_call": 5,
        "real_permission": 6,
        "call": 7,
        "url": 8
    }

    features_map = {x: 0 for x in range(1, 9)}
    for l in lines:
        if l != "\n":
            set = l.split("::")[0]
            features_map[FEATURES_SET[set]] += 1
    features = []
    for i in range(1, 9):
        features.append(features_map[i])
    return features


def read_sha_files():
    feature_count = []
    for filename in os.listdir(dir_of_files):
        sha_data = open(dir_of_files+ filename)
        feature_count.append([filename] + count_feature_set(sha_data))
        sha_data.close()
    return feature_count


def create_csv_for_sha_data():
    header = ['sha256', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8']
    with open(feature_of_counts_temp, "wt", newline ='') as file:
        writer = csv.writer(file, delimiter=',')
        writer.writerow(i for i in header)
        for j in read_sha_files():
            writer.writerow(j)



#Create the temporary feature set file
create_csv_for_sha_data()
data = pd.read_csv(known_malware_files)
sha_column = data["sha256"]

feature_vectors_data = pd.read_csv(feature_of_counts_temp)
sha256_data = feature_vectors_data['sha256']

mask = np.in1d(sha256_data, sha_column)


#creates the full feature vectors file containing both inputs and output (malware or not)
#this file is created as a merger of the temporary file created and the output generated above
malware = pd.DataFrame({'malware' : mask })
feature_vectors_data = feature_vectors_data.merge(malware, left_index = True, right_index = True)
feature_vectors_data.to_csv(feature_of_counts)
