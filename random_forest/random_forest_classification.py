# -*- coding: utf-8 -*-
"""
Created on Sat Sep 19 11:45:27 2020

@author: Vineet
"""

#ensure sklearn, tree is installed

# Pandas is used for data manipulation
import pandas as pd
import pprint

# Use numpy to convert to arrays
import numpy as np

# Using Skicit-learn to split data into training and testing sets
from sklearn.model_selection import train_test_split

# Import the model we are using
from sklearn.ensemble import RandomForestRegressor

# Import tools needed for visualization
from sklearn.tree import export_graphviz
import pydot

import matplotlib.pyplot as plt

from IPython.display import Image  
from sklearn import tree
import pydotplus

import os

# Read in data and display first 5 rows
pp = pprint.PrettyPrinter(indent=1)
features = pd.read_csv('features_regression.csv')
pp.pprint(features.head(5))

print('The shape of our features is:', features.shape)

# Descriptive statistics for each column
print(features.describe())

features_dataframe = features.describe()
features_dataframe.to_csv('features_dataframe.csv')

#counting empty values
print("The number of empty valued cells in each column")
print(features_dataframe.isnull().sum())

# One-hot encode the data using pandas get_dummies
#features = pd.get_dummies(features)
# Display the first 5 rows of the last 12 columns
#features.iloc[:,5:].head(5)

# Labels are the values we want to predict
labels = np.array(features['CVSS3_Base_Score'])

# Remove the labels from the features
# axis 1 refers to the columns
features= features.drop('CVSS3_Base_Score', axis = 1)

features= features.drop('cvssV3_baseSeverity_MEDIUM', axis = 1)
features= features.drop('cvssV3_baseSeverity_LOW', axis = 1)
features= features.drop('cvssV3_baseSeverity_CRITICAL', axis = 1)
features= features.drop('cvssV3_baseSeverity_HIGH', axis = 1)

# Saving feature names for later use
feature_list = list(features.columns)

# Convert to numpy array
features = np.array(features)

# Split the data into training and testing sets
train_features, test_features, train_labels, test_labels = train_test_split(features, labels, test_size = 0.20, random_state = 42)


print('Confirming that the number of training features match the testing')
print('Training Features Shape:', train_features.shape)
print('Training Labels Shape:', train_labels.shape)
print('Testing Features Shape:', test_features.shape)
print('Testing Labels Shape:', test_labels.shape)

#print("Establising baseline - Using CVSS2 as the baseline score", feature_list.index('CVSS3_Base_Score'), type(feature_list.index('CVSS3_Base_Score')))

# The baseline predictions are the historical averages
#baseline_preds = test_features[:, feature_list.index('CVSS3_Base_Score')]

#print("baseline_preds",baseline_preds,type(baseline_preds))
#print("test_labels",test_labels,type(test_labels))


# Baseline errors, and display average baseline error
#baseline_errors = abs(baseline_preds - test_labels)
#print('Average baseline error: ', round(np.mean(baseline_errors), 2))

# Instantiate model with 1000 decision trees
rf = RandomForestRegressor(n_estimators = 1000, random_state = 42)
# Train the model on training data
rf.fit(train_features, train_labels);

# Use the forest's predict method on the test data
predictions = rf.predict(test_features)
# Calculate the absolute errors
errors = abs(predictions - test_labels)
# Print out the mean absolute error (mae)
print('Mean Absolute Error:', round(np.mean(errors), 2), 'degrees.')

# Calculate mean absolute percentage error (MAPE)
mape = 100 * (errors / test_labels)
# Calculate and display accuracy
accuracy = 100 - np.mean(mape)
print('Accuracy:', round(accuracy, 2), '%.')

# Pull out one tree from the forest
regressor_tree_object = rf.estimators_[5]

# Export the image to a dot file
dot_data = export_graphviz(regressor_tree_object, out_file = None, feature_names = feature_list, rounded = True, precision = 1)

export_graphviz(regressor_tree_object, out_file = 'tree.dot', feature_names = feature_list, rounded = True, precision = 1)

# Use dot file to create a graph
(graph, ) = pydot.graph_from_dot_file('tree.dot')

# This doesn't seem to work for some reason. Write graph to a png file
#graph.write_png('tree.png')

#graph is a None type object.
# # Draw graph
# graph = pydotplus.graph_from_dot_data(dot_data)  
# # Show graph
# Image(graph.create_png())


# Limit depth of tree to 3 levels
rf_small = RandomForestRegressor(n_estimators=10, max_depth = 3)
rf_small.fit(train_features, train_labels)
# Extract the small tree
tree_small = rf_small.estimators_[5]
# Save the tree as a png image
export_graphviz(tree_small, out_file = 'small_tree.dot', feature_names = feature_list, rounded = True, precision = 1)
#(graph, ) = pydot.graph_from_dot_file('small_tree.dot')
#graph.write_png('small_tree.png');

# Get numerical feature importances
importances = list(rf.feature_importances_)
# List of tuples with variable and importance
feature_importances = [(feature, round(importance, 2)) for feature, importance in zip(feature_list, importances)]
# Sort the feature importances by most important first
feature_importances = sorted(feature_importances, key = lambda x: x[1], reverse = True)
# Print out the feature and importances 
[print('Variable: {:20} Importance: {}'.format(*pair)) for pair in feature_importances];


# New random forest with only the two most important variables
rf_most_important = RandomForestRegressor(n_estimators= 1000, random_state=42)
# Extract the two most important features
important_indices = [feature_list.index('cvssV3_integrityImpact_HIGH'), feature_list.index('cvssV3_attackVector_NETWORK')]
train_important = train_features[:, important_indices]
test_important = test_features[:, important_indices]
# Train the random forest
rf_most_important.fit(train_important, train_labels)
# Make predictions and determine the error
predictions = rf_most_important.predict(test_important)
errors = abs(predictions - test_labels)
# Display the performance metrics
print('Mean Absolute Error:', round(np.mean(errors), 2), 'degrees.')
mape = np.mean(100 * (errors / test_labels))
accuracy = 100 - mape
print('Accuracy:', round(accuracy, 2), '%.')

# Set the style
plt.style.use('fivethirtyeight')
# list of x locations for plotting
x_values = list(range(len(importances)))
# Make a bar chart
plt.bar(x_values, importances, orientation = 'vertical')
# Tick labels for x axis
plt.xticks(x_values, feature_list, rotation='vertical')
# Axis labels and title
plt.ylabel('Importance'); plt.xlabel('Variable'); plt.title('Variable Importances');