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

def get_series(resp, class_name, ext = '',col = 0):
    soup = bs.BeautifulSoup(resp.text, 'lxml') 
    print("The search begins here")

    #for t in soup.find_all('table',{'cellpadding':'2'}):
    for t in soup.find_all('title'):    
        #i += 1
        #if i == 2:
        table = t
    
    vendor_name = str(table)
    vendor_name = str(vendor_name[7:len(str(vendor_name))-35])
    print("Working on Vendor Name",vendor_name)    
    
    for t in soup.find_all('table',{'class':class_name}):   
        table = t
    
    tickers = []
    tickers2 = []
    tickers_dict = {}
            
    for row in table.findAll('tr',{'class':'srrowns'})[0:]:
        ticker_col1 = vendor_name   
        ticker_col2 = row.findAll('td')[col].text.strip('\n')                
        tickers.append(ticker_col1)
        tickers2.append(ticker_col2)
        tickers_dict[ticker_col2] = ticker_col1
        
    with open("vendor_vuln_mapping.pickle","wb") as f:
        pickle.dump(tickers,f)
    
    print("\nSUCCESS: Series List of vulnerabilities fetched!\n", tickers_dict)  
    return pd.Series(tickers_dict)

def fetch_contents(website_link, ext, col, class_name = ''):  
    resp = requests.get(website_link)
    #'tbldata14 bdrtpg' 'wikitable sortable'
    print("Response",resp)
    return get_series(resp, class_name, ext, col)

def set_vendor_vulnerability_mapping():
    global website_link
    global class_name
    global col
    global output_filename
    global ext
    
    website_link = 'https://www.cvedetails.com/vulnerability-list/vendor_id-26/year-2003.html' 
    #website_link = 'https://www.cvedetails.com/vulnerability-list.php?vendor_id=27&product_id=&version_id=&page=7&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=2019&month=0&cweid=0&order=1&trc=668&sha=6ed5a211e30708195fc5752650a056f7c806d8f0'      
    class_name = 'searchresults sortable'
    col = 1
    output_filename = 'output/Vendor_Vulnerability_Mapping.csv'
    ext = ''

def get_vendor_vulnerability_mapping(number_of_vendors):
    set_vendor_vulnerability_mapping()  
    
    vendor_vulnerability_mapping_final = pd.Series([])
    #loop through each vendor number and year    
    for vendor_id in range(1,number_of_vendors):
        for year_number in range(1999,2021):
            print("Working on Vendor#",vendor_id,"for the year",year_number)
            website_link = 'https://www.cvedetails.com/vulnerability-list/vendor_id-'+str(vendor_id)+'/year-'+str(year_number)+'.html'  
            vendor_vulnerability_mapping = fetch_contents(website_link, ext, col, class_name) 
            
            print("This is the vendor_vulnerability_mapping",vendor_vulnerability_mapping)
            
            vendor_vulnerability_mapping_final = vendor_vulnerability_mapping_final.append(vendor_vulnerability_mapping)
            
            print("This is the vendor_vulnerability_mapping_final",vendor_vulnerability_mapping_final)
            
            
    return vendor_vulnerability_mapping_final


def vendor_mapping_download(number_of_vendors = 1):    
    print("Fetch mapping between Vulnerabilities and Exploits")                             
    mapping_outputfile_name = "output/CVSS_Vendor_Mapping.csv"
    vendor_vulnerability_mapping = get_vendor_vulnerability_mapping(number_of_vendors)
    
    print("The data scraped: Exploit-Vulnerability mapping",vendor_vulnerability_mapping)
    
    with open(mapping_outputfile_name, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["CVE_ID","Vendor_Name"])

    for exploit,vulnerability in vendor_vulnerability_mapping.items() :
        print("CVE_ID",exploit)
        print("Vendor Name",vulnerability)
        #Load into a CSV file
        with open(mapping_outputfile_name, 'a+', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                        exploit,
                        vulnerability
                        ])

#change this number
number_of_vendors = 150    #there are 20953 vendors listed in this website (cvedetails.com) 
vendor_mapping_download(number_of_vendors)