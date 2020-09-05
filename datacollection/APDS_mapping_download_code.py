import pandas as pd
import pickle
import bs4 as bs
import pickle
import requests
import csv

def get_series(resp, class_name, ext = '',col = 0):
    soup = bs.BeautifulSoup(resp.text, 'lxml') 
    print("reached here")
    i = 0
    for t in soup.find_all('table',{'cellpadding':'2'}):
        i += 1
        if i == 2:
            table = t
    print("and here")

    tickers = []
    tickers2 = []
    tickers_dict = {}
    for row in table.findAll('tr')[1:]:
        ticker_col1 = row.findAll('td')[col].text.strip('\n')   
        ticker_col2 = row.findAll('td')[col + 1].text.strip('\n')                   
        tickers.append(ticker_col1)
        tickers2.append(ticker_col2)
        tickers_dict[ticker_col1] = ticker_col2
        
    with open("exploit_vuln_mapping.pickle","wb") as f:
        pickle.dump(tickers,f)
    
    print("\nSUCCESS: Series List of vulnerabilities fetched!\n")  
    return pd.Series(tickers_dict)

def fetch_contents(website_link, ext, col, class_name = ''):  
    resp = requests.get(website_link)
    #'tbldata14 bdrtpg' 'wikitable sortable'
    return get_series(resp, class_name, ext, col)

def set_exploit_vulnerability_mapping():
    global website_link
    global class_name
    global col
    global output_filename
    global ext
    
    website_link = 'https://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html'       
    class_name = ''
    col = 0
    output_filename = 'output/Exploit_Vulnerability_Mapping.csv'
    ext = ''

def get_exploit_vulnerability_mapping():
    set_exploit_vulnerability_mapping()    
    exploit_vulnerability_mapping = fetch_contents(website_link, ext, col, class_name)    
    return exploit_vulnerability_mapping


def exploit_mapping_download():    
    print("Fetch mapping between Vulnerabilities and Exploits")                             
    mapping_outputfile_name = "output/CVSS_Exploit_Mapping.csv"
    exploit_vulnerability_mapping = get_exploit_vulnerability_mapping()
    
    print("The data scraped: Exploit-Vulnerability mapping",exploit_vulnerability_mapping)
    
    with open(mapping_outputfile_name, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Exploit_ID","List_of_Vulnerabilities"])
    
    for exploit,vulnerability in exploit_vulnerability_mapping.items() :
        #print("Ex",exploit)
        #print the elements being loaded into the output file       
        #print("Exploit::",exploit,
        #      "List_of_Vaulnerabilities::",vulnerability    
        #      )
    
        #Load into a CSV file
        with open(mapping_outputfile_name, 'a+', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                        exploit,
                        vulnerability
                        ])