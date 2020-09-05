# Data cleanup routines for IIMC APDS03 Project for Group 8
# This script has the following functions for CVE Vulnerabilities
#
# 1. remove duplicates
# 2. remove descriptions with REJECT + DISPUTED
# 3.Remove blank CVS3 & CVS2 base scores
# Author: Sai Yanamandra, 5th Sept, 2020

import pandas as pd

#Routine to remove duplciates
def remvoeDuplicates():
    df = pd.read_csv('myfile.csv')
    df.drop_duplicates(inplace=True)
    df.to_csv('myfile.csv', index=False)


def main():
    print("Cleaning up Data...")

    #range of years to download
    start_year = '../datacollection/'
    end_year = 2020   #at the moment, latest year can be 2020
              
if __name__ == '__main__':
    main() 