# Data cleanup routines for IIMC APDS03 Project for Group 8
# This script performs the following activiites from the  CVE Vulnerabilities dataset 
#
# 1. remove duplicates
# 2. remove descriptions with REJECT + DISPUTED
# 3.Remove blank CVS3 & CVS2 base scores
# Author: Sai Yanamandra, 5th Sept, 2020

import pandas as pd

#the csv to be cleaned
input_csv = '..\datacollection\output\CVSS_Last20_years_combined.csv'

#Routine to perform the cleanup
def cleanUp():
    df = pd.read_csv(input_csv)

    #rename the descriptions column value
    df.rename(columns={"description_data_0_value": "description"}, inplace = True)

    #remove the duplicate rows just in case
    df.drop_duplicates(inplace=True)


    #drop the rows that are rejected or under dispute, in place in the same data frame
    df =  df[(df['description'].str.contains('REJECT') == False)]
    df =  df[(df['description'].str.contains('DISPUTED') == False)]

    #drop the rows that have blanks for cvss3 and cvss2 base scores
    df = df[ df['cvssV3_baseScore'].str.strip().astype(bool) ]
    df = df[ df['cvssV2_baseScore'].str.strip().astype(bool) ]

    #generate the output file without indexes
    df.to_csv("D:\\repos\\APDSProject\\MLTuning\\datacleanup\\cvss_final_dataset.csv", index=False, encoding='utf8')

def main():
    print("Cleaning up Data...")

    #clean up the data by deleting the unwanted rows
    cleanUp()
    
if __name__ == '__main__':
    main() 