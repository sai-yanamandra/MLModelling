# -*- coding: utf-8 -*-
"""
Created on Tue Sep  1 12:00:35 2020

@author: Vineet
"""

import pandas as pd
import pickle
import bs4 as bs
import pickle
import requests
import csv

import os.path
from os import path


def get_series(cve_id_string, resp, class_name, ext = '',col = 0):
    soup = bs.BeautifulSoup(resp.text, 'lxml')
     
    try:
        for t in soup.find_all('table',{'id':'vulnversconuttable'}):
            table = t
            print("t",table)
    except:
        print("Couldn't find the regular table, there is something unusual here")
        
    tickers = []
    tickers_dict = {}
    
    try:        
        for row in table.findAll('tr')[1:]:
            ticker_col1 = row.findAll('td')[col].text.strip('\n') 
            ticker_col2 = row.findAll('td')[col+1].text.strip('\n') 
            ticker_col3 = cve_id_string 
            
            tickers = ticker_col1,ticker_col2
            tickers_dict[ticker_col3] = tickers
    except:
        tickers = 'NOT AVAILABLE ON WWW.CVEDETAILS.COM','NOT AVAILABLE ON WWW.CVEDETAILS.COM'
        tickers_dict[cve_id_string] = tickers
        
    with open("vendor_vuln_mapping.pickle","wb") as f:
        pickle.dump(tickers,f)
    
    tickers_series = pd.Series(tickers_dict)
    tickers_series.append(pd.Series([cve_id_string]))
    print("FOUND: Found the product details", tickers)  
    return pd.Series(tickers_series)

def fetch_contents(cve_id_string, website_link, ext, col, class_name = ''):
    resp = requests.get(website_link)
    print("The response is (200- GOOD):",resp)
    #'tbldata14 bdrtpg' 'wikitable sortable'
    return get_series(cve_id_string, resp, class_name, ext, col)

def set_vendor_vulnerability_mapping():
    global website_link
    global class_name
    global col
    global output_filename
    global ext
    
    website_link = 'https://www.cvedetails.com/cve/CVE-2018-3732/' 
    class_name = 'listtable'
    col = 0
    output_filename = 'output/Vulnerability_Vendor_Product_Mapping.csv'
    ext = ''

def get_vendor_vulnerability_mapping(cve_id_string):
    set_vendor_vulnerability_mapping()  
    
    vendor_vulnerability_mapping_final = pd.Series([])
    #loop through each vendor number and year    
    #    for cve_id in range(1,cve_id_list):
    #        for year_number in range(1999,2021):

    print("\n\nOPENING:Now fetching Vendor and Product information for",cve_id_string,"\n\n\n")
    
    website_link = 'https://www.cvedetails.com/cve/'+str(cve_id_string)+'/'  
    vendor_vulnerability_mapping = fetch_contents(cve_id_string, website_link, ext, col, class_name) 
    
    #vendor_vulnerability_mapping_final = vendor_vulnerability_mapping_final.append(pd.Series(cve_id_string))
    vendor_vulnerability_mapping_final = vendor_vulnerability_mapping_final.append(vendor_vulnerability_mapping)
                
    return vendor_vulnerability_mapping_final


def vendor_mapping_download(cve_id_list):    
    print("\n\nFetch mapping between Vulnerabilities and Vendor/Product")                             
    mapping_outputfile_name = "output/CVSS_Vuln_Vendor_Product_Mapping.csv"
    vuln_vendor_prod_mapping = pd.Series([])
    for cve_id in cve_id_list:
        cve_id_String = cve_id
        cve_id = pd.Series(cve_id)
        vuln_vendor_prod_mapping = vuln_vendor_prod_mapping.append(get_vendor_vulnerability_mapping(cve_id_String))
        
        if not path.exists(mapping_outputfile_name):
             with open(mapping_outputfile_name, 'w+', newline='') as file:
                writer = csv.writer(file)
                print("File doesn't exist, creating file with headers")
                writer.writerow(["CVE_ID","Vendor_Name","Product_Name"])
        
        with open(mapping_outputfile_name, 'a+', newline='') as file:
            writer = csv.writer(file)
            #writer.writerow(["CVE_ID","Vendor_Name","Product_Name"])
    
    for cve,product in vuln_vendor_prod_mapping.items():
        print("\nLOADING: Currently Working on CVE_ID",cve)
        print("The Vendor Name is",product[0])
        print("The Product Name is",product[1],"\n")
        #Load into a CSV file
        with open(mapping_outputfile_name, 'a+', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                        cve,
                        product[0],
                        product[1]
                        ])
        print("LOADED: Success",cve,"complete\n")

#expects a series of CVE ids
def get_vendor_product_mapping(cve_id_list = {'CVE-2018-3732','CVE-2018-3752'}):
    print("Fetching Vendor and Product details for",cve_id_list)
    vendor_mapping_download(cve_id_list)
    print("SUCCESS:Fetch complete! Woot! Woot!")