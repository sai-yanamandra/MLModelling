# Data cleanup routines for IIMC APDS03 Project for Group 8
# This script performs the decision tree modelling for CVSS to 
# provide new way of classifying CVE's whith roughly categorizing 2% to 3%
# of CVE's under critical category
#
# Author: Sai Yanamandra, 21 Sept, 2020

import pandas as pd
pd.options.mode.chained_assignment = None  # default='warn'
import numpy as np

#%matplotlib inline
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

from sklearn import preprocessing
from sklearn.model_selection import cross_val_score, cross_val_predict
from sklearn.metrics import accuracy_score, classification_report
from sklearn.metrics import confusion_matrix, roc_auc_score


def calculateSeverityScore(row):
    #baseScore = score
    if (row['cvssV3_attackVector'] == "NETWORK" and row['cvssV3_availabilityImpact'] != "NONE" and row['cvssV3_integrityImpact'] == "HIGH" and row['cvssV3_privilegesRequired'] == "NONE" and row['cvssV3_userInteraction'] == "NONE"):
        return 'CRITICAL'
    elif (row['cvssV3_attackVector'] == 'NETWORK' and row['cvssV3_availabilityImpact'] != 'NONE' and row['cvssV3_integrityImpact'] == 'HIGH' and row['cvssV3_privilegesRequired'] == 'NONE' and row['cvssV3_userInteraction'] == 'REQUIRED'):
        return 'HIGH'
    elif (row['cvssV3_attackVector'] == 'NETWORK' and row['cvssV3_availabilityImpact'] != 'NONE' and row['cvssV3_integrityImpact'] == 'HIGH' and row['cvssV3_privilegesRequired'] != 'NONE'):
        return 'HIGH'
    elif (row['cvssV3_attackVector'] != 'NETWORK' and row['cvssV3_integrityImpact'] == 'HIGH' and row['cvssV3_privilegesRequired'] == 'NONE'):
        return 'HIGH'
    elif (row['cvssV3_attackVector'] == 'NETWORK' and row['cvssV3_integrityImpact'] == 'HIGH' and row['cvssV3_privilegesRequired'] != 'NONE'):
        return 'HIGH'
    elif (row['cvssV3_availabilityImpact'] != 'HIGH' and row['cvssV3_integrityImpact'] != 'HIGH' and row['cvssV3_privilegesRequired'] == 'NONE' and row['cvssV3_userInteraction'] == 'NONE'):
        return 'HIGH'
    elif (row['cvssV3_integrityImpact'] != 'HIGH' and row['cvssV3_privilegesRequired'] == 'NONE' and row['cvssV3_scope'] == 'CHANGED' and row['cvssV3_userInteraction'] == 'REQUIRED'):
        return 'LOW'        
    elif (row['cvssV3_integrityImpact'] != 'HIGH' and row['cvssV3_userInteraction'] == 'REQUIRED' and row['cvssV3_privilegesRequired'] == 'NONE' and row['cvssV3_scope'] == 'UNCHANGED'):
        return 'LOW'         
    elif (row['cvssV3_confidentialityImpact'] != 'LOW' and row['cvssV3_integrityImpact'] != 'HIGH' and row['cvssV3_privilegesRequired'] != 'NONE'):
        return 'LOW'            
    elif (row['cvssV3_confidentialityImpact'] == 'LOW' and row['cvssV3_integrityImpact'] != 'HIGH' and row['cvssV3_privilegesRequired'] != 'NONE'):
        return 'LOW'
    else:
        return 'LOW'

def print_score(clf, X_train, X_test, y_train, y_test, train=True):
    '''
    v0.1 Follow the scikit learn library format in terms of input
    print the accuracy score, classification report and confusion matrix of classifier
    '''
    lb = preprocessing.LabelBinarizer()
    lb.fit(y_train)
    if train:
        '''
        training performance
        '''
        res = clf.predict(X_train)
        print("Train Result:\n")
        print("accuracy score: {0:.4f}\n".format(accuracy_score(y_train, 
                                                                res)))
        print("Classification Report: \n {}\n".format(classification_report(y_train, 
                                                                            res)))
        print("Confusion Matrix: \n {}\n".format(confusion_matrix(y_train, 
                                                                  res)))
        print("ROC AUC: {0:.4f}\n".format(roc_auc_score(lb.transform(y_train), 
                                                      lb.transform(res))))

        #res = cross_val_score(clf, X_train, y_train, cv=10, scoring='accuracy')
        #print("Average Accuracy: \t {0:.4f}".format(np.mean(res)))
        #print("Accuracy SD: \t\t {0:.4f}".format(np.std(res)))
        
    elif train==False:
        '''
        test performance
        '''
        res_test = clf.predict(X_test)
        print("Test Result:\n")        
        print("accuracy score: {0:.4f}\n".format(accuracy_score(y_test, 
                                                                res_test)))
        print("Classification Report: \n {}\n".format(classification_report(y_test, 
                                                                            res_test)))
        print("Confusion Matrix: \n {}\n".format(confusion_matrix(y_test, 
                                                                  res_test)))   
        print("ROC AUC: {0:.4f}\n".format(roc_auc_score(lb.transform(y_test), 
                                                      lb.transform(res_test))))        

def checkConsequence(severity):
   try:
      if (
            #Stability
            ((severity.find(' Crash, Exit, or Restart') != -1) and
             (severity.find('Instability') != -1)) or
            
            #Access
            ((severity.find('Read Files or Directories') != -1) and 
             (severity.find('Modify Files or Directories') != -1))  or 

            #Authorization
             ((severity.find('Execute Unauthorized Code or Commands') != -1) and 
             (severity.find('Gain Privileges or Assume Identity') != -1))
         ):
         return 1
      else:
         return 0   
   except AttributeError:
      return 0

def updateSeverity(row):
   try:
        if (row['Severity_Score'] == "CRITICAL" and row['Super_Severity_Score'] == 1):
                return 'CRITICAL'
        elif (row['Severity_Score'] == "CRITICAL" and row['Super_Severity_Score'] == 0):
                return 'HIGH'  
        else:
            return  row['Severity_Score']
   except AttributeError:
      return 0      


def main():
    print("python main function")

    df = pd.read_csv("D:\\repos\\APDSProject\\MLTuning\\datacleanup\\cvss_final_dataset.csv")

    vendor = pd.read_csv("D:\\repos\\APDSProject\\MLTuning\\datacollection\\vendor_cve_map.csv")
    vendor.rename(columns = {'CVE ID':'data_meta_ID'}, inplace = True)
    df_outer = pd.merge(df, vendor, on='data_meta_ID', how='left')
    df_outer.drop_duplicates(subset=['data_meta_ID'])

    remove_list = ['timestamp','data_type','data_format', 'data_version','data_meta_ASSIGNER','cvssV3_version','cvssV3_vectorString','cvssV2_version','cvssV2_vectorString']

    cvss3_features = ['cvssV3_attackVector', 'cvssV3_attackComplexity', 'cvssV3_privilegesRequired', 'cvssV3_userInteraction', 'cvssV3_scope','cvssV3_confidentialityImpact', 'cvssV3_integrityImpact','cvssV3_availabilityImpact', 'cvssV3_baseScore', 'cvssV3_baseSeverity',      'baseMetricV3_exploitabilityScore', 'baseMetricV3_impactScore', ]

    cvss3_df = df[cvss3_features]

    cvssv3_numerical_col = list(cvss3_df.describe().columns)
    cvssv3_categorical_col = list(set(cvss3_df.columns).difference(cvssv3_numerical_col))
    cvssv3_categorical_col.remove('cvssV3_baseSeverity')

    cvssv3_model_df= cvss3_df[cvssv3_categorical_col]

    #Read the CWE data frame to extract the Consequence column

    #CWE_df = pd.read_csv("D:\\repos\\APDSProject\\MLTuning\\datacollection\\CVSS-Base.csv")
    CWE_df = pd.read_csv("D:\\repos\\APDSProject\\MLTuning\\modeling\\CWE_Inputs.csv")
    CWE_df_new = CWE_df[CWE_df['Common Consequences'].notnull()]
    cvssv3_model_df['Consequences']= CWE_df_new['Common Consequences']

    #Perform One Hot Encoding
    X = pd.get_dummies(cvssv3_model_df[cvssv3_categorical_col])

    #Apply the Consequence Factor
    cvssv3_model_df['Super_Severity_Score'] = cvssv3_model_df.apply(lambda row: checkConsequence(row['Consequences']),axis=1)
    print(cvssv3_model_df['Super_Severity_Score'].value_counts())
    X['Super_Severity_Score'] = cvssv3_model_df['Super_Severity_Score']

    #Prepare the Dependent Variable
    cvssv3_model_df['Severity_Score'] = cvssv3_model_df.apply(lambda row: calculateSeverityScore(row),axis=1)

    cvssv3_model_df['New_Severity_Score'] = cvssv3_model_df.apply(lambda row: updateSeverity(row),axis=1)

    print(cvssv3_model_df['Severity_Score'].value_counts())
    print(cvssv3_model_df['New_Severity_Score'].value_counts())

    severity_to_num = {'CRITICAL': 1,
                        'HIGH': 2,
                        'LOW': 3}
    cvssv3_model_df['Severity_Score_Num'] = cvssv3_model_df['New_Severity_Score'].map(severity_to_num)
    cvssv3_model_df.rename(columns = {'New_Severity_Score':'Severity_Score_Text'}, inplace = True)
    cvssv3_model_df.rename(columns = {'Severity_Score_Num':'New_Severity_Score'}, inplace = True)

    Y = cvssv3_model_df['New_Severity_Score']

    #Y.to_csv("classes.csv",index=False,encoding='utf8')
    classes = pd.DataFrame(Y)
    #Y['CVE_ID'] = df['data_meta_ID']
    #Y.size
    classes['CVE_ID'] = df['data_meta_ID']
    classes.head
    classes.to_csv("classes.csv",index=False,encoding='utf8')


    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.1, random_state=42) # 70% training and 30% test


    # Create Decision Tree classifer object
    clf = DecisionTreeClassifier(criterion="entropy",splitter="best",max_depth=7,random_state=42)

    # Train Decision Tree Classifer
    clf = clf.fit(X_train,y_train)

    #Predict the response for test dataset
    y_pred = clf.predict(X_test)

    print_score(clf, X_train, X_test, y_train, y_test, train=False)

    ynew = clf.predict(X)

    classes_new = pd.DataFrame(ynew)

    classes_new['CVE_ID'] = df['data_meta_ID']
    

    classes_new.rename(columns = {0:'Severity_Score'}, inplace = True)


    #classes_new.columns
    print(classes_new['Severity_Score'].value_counts())
    classes_new.to_csv("classes_new.csv",index=False,encoding='utf8')
    
    print("Number of Nodes")
    print(clf.tree_.node_count)

if __name__ == '__main__':
    main() 








