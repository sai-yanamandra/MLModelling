# Data cleanup routines for IIMC APDS03 Project for Group 8
# This script performs the following activiites from the  CVE Vulnerabilities dataset 
#
# 1. Downloads Top 50 Vendors from CVE - Details
# 2. Download the CVE-ID's of top 50 vendors page by page and concatenate into a singls csv file
# 3.Remove blank CVS3 & CVS2 base scores
# Author: Sai Yanamandra, 21 Sept, 2020

import requests
import pandas as pd
import glob
import os



def getVendorSpecificCVEs(vendor,noOfVulnerabilities,vendorID,sha):
    print("Starting to collect " + vendor +" realted CVE's")
    pages = int(noOfVulnerabilities / 50) + 2; 
    #https://www.cvedetails.com/vulnerability-list.php?vendor_id=1224&product_id=&version_id=&page=2&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc=4572&sha=5682ebdc8f19bcdf9764395cdda62a9d71238a49
    dfs = []
    url1 = 'https://www.cvedetails.com/vulnerability-list.php?vendor_id='
    url2 = '&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc='
    for index in range(1,pages):   
        print("Reading Page ",index)
        url = url1 + str(vendorID) + '&product_id=&version_id=&page='+ str(index) + url2 + str(noOfVulnerabilities) + '&sha=' + sha
        #print(url)
        html = requests.get(url).content
        df_list = pd.read_html(html)
        df = df_list[-1]
        df['Vendor']=vendor
        df['VendorId']=vendorID
        dfs.append(df.iloc[::2])

    bigframe = pd.concat(dfs,ignore_index=True)
    bigframe.to_csv('.\\VendorMapping\\'+vendor+'.csv') 

def concatenateVendors():
    path ="D:\\repos\\APDSProject\\MLTuning\\datacollection\\VendorMapping"
    filenames = glob.glob(path + "/*.csv")
    vendors = []

    for filename in filenames:
        vendors.append(pd.read_csv(filename))

    # Concatenate all data into one DataFrame
    biggest_frame = pd.concat(vendors, ignore_index=True)
    biggest_frame.to_csv('vendor_cve_map.csv') 


def main():
    print("Collecting the Vendors")

    if not os.path.exists('VendorMapping'):
        os.makedirs('VendorMapping')

    #Loop through the top 50 vendors
    vendors = pd.read_csv("D:\\repos\\APDSProject\\MLTuning\\datacollection\\vendors.csv")
    #vendors.info()
    for index, row in vendors.head(n=50).iterrows():
         print(index, row['Vendor Name'], row['Number of Vulnerabilities'],row['Vendor ID'], row['Sha'])
         getVendorSpecificCVEs(row['Vendor Name'], row['Number of Vulnerabilities'],row['Vendor ID'], row['Sha'])

    concatenateVendors()

if __name__ == '__main__':
    main() 