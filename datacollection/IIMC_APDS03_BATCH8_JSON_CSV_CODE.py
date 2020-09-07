# -*- coding: utf-8 -*-
"""
Created on Fri Jul  3 14:41:44 2020

@author: IIMC APDS Group 8 - Batch 03
"""

import json 
import csv
import requests 
from flatten_json import flatten
from zipfile import ZipFile
import warnings
import pandas as pd
import pickle
import bs4 as bs
import os.path
from os import path

import APDS_mapping_download_code

def download_zip_from_url(url, save_path, chunk_size=128):
    r = requests.get(url, stream=True)
    with open(save_path, 'wb') as fd:
        for chunk in r.iter_content(chunk_size=chunk_size):
            fd.write(chunk)
    print("SUCCESS: Download of zipped file",save_path,"was a success! Woot with Sai!")

def unzip_file(zipped_filename):    
    try:
        # create a ZipFile Object and load the zipped contents to it
         with ZipFile(zipped_filename, 'r') as zipObj:
             # Extract all the contents of zip file in current directory        
             zipObj.extractall('downloads')
             print("\nLOG: Successfully unzipped contents for",zipped_filename,"!")
    except:
        print("\nFAIL: Unzip failed!")
              
def convert_JSON_to_CSV(json_download_filename, csv_file, combined_csv, limit_download=10):  
    # Opening JSON file and load the data 
    with open(json_download_filename, encoding="utf8") as json_file: 
        data = json.load(json_file) 
    
    #iteratively flatten the JSON file    
    dict_data = flatten(data)
    
    #these will become the column names in the CSV file    
    csv_columns_headers = ['type', 'format', 'version', 'timestamp', 'data_type', 'data_format', 'data_version', 'data_meta_ID', 'data_meta_ASSIGNER', 'problemtype_description_lang', 
    'problemtype_value', 'reference_data_url', 'reference_data_name', 'reference_data_refsource', 'reference_data_tags', 'description_data_0_lang', 'description_data_0_value', 'configurations_CVE_data_version', 'configurations_nodes_0_operator', 'cpe_match_0_vulnerable', 'cpe_match_0_cpe23Uri', 
    'cpe_match_1_vulnerable', 'cpe_match_1_cpe23Uri', 'cpe_match_2_vulnerable', 'cpe_match_2_cpe23Uri', 'cpe_match_3_vulnerable', 'cpe_match_3_cpe23Uri','cvssV3_version', 'cvssV3_vectorString', 'cvssV3_attackVector', 'cvssV3_attackComplexity', 'cvssV3_privilegesRequired', 
    'cvssV3_userInteraction', 'cvssV3_scope', 'cvssV3_confidentialityImpact', 'cvssV3_integrityImpact', 'cvssV3_availabilityImpact', 'cvssV3_baseScore', 'cvssV3_baseSeverity', 'baseMetricV3_exploitabilityScore', 'baseMetricV3_impactScore', 'cvssV2_version', 'cvssV2_vectorString', 
    'cvssV2_accessVector', 'cvssV2_accessComplexity', 'cvssV2_authentication', 'cvssV2_confidentialityImpact', 'cvssV2_integrityImpact', 'cvssV2_availabilityImpact', 'cvssV2_baseScore', 'baseMetricV2_severity', 'baseMetricV2_exploitabilityScore', 'baseMetricV2_impactScore', 'baseMetricV2_acInsufInfo', 
    'baseMetricV2_obtainAllPrivilege', 'baseMetricV2_obtainUserPrivilege', 'baseMetricV2_obtainOtherPrivilege', 'baseMetricV2_userInteractionRequired', 'publishedDate', 'lastModifiedDate']
    
    csv_columns = ['key_1','key_2','key_3','key_4','key_5','key_6','key_7','key_8','key_9','key_10','key_11','key_12','key_13','key_14','key_15','key_16','key_17','key_18','key_19','key_20',
    'key_21','key_22','key_23','key_24','key_25','key_26','key_27','key_28','key_29','key_30','key_31','key_32','key_33','key_34','key_35','key_36','key_37','key_38','key_39',               'key_40',
    'key_41','key_42','key_43','key_44','key_45','key_46','key_47','key_48','key_49','key_50','key_51','key_52','key_53','key_54','key_55','key_56','key_57','key_58','key_59','key_60']
    
    
    #these will become the column names in the COMBINED CSV file    
    combined_csv_columns_headers = ['timestamp', 'data_type', 'data_format', 'data_version', 'data_meta_ID', 'data_meta_ASSIGNER', 'problemtype_value', 'reference_data_url','reference_data_refsource', 'description_data_0_value',  
    'cvssV3_version', 'cvssV3_vectorString', 'cvssV3_attackVector', 'cvssV3_attackComplexity', 'cvssV3_privilegesRequired', 'cvssV3_userInteraction', 'cvssV3_scope', 'cvssV3_confidentialityImpact', 'cvssV3_integrityImpact', 'cvssV3_availabilityImpact', 
    'cvssV3_baseScore', 'cvssV3_baseSeverity', 'baseMetricV3_exploitabilityScore', 'baseMetricV3_impactScore', 'cvssV2_version', 'cvssV2_vectorString','cvssV2_accessVector', 'cvssV2_accessComplexity', 'cvssV2_authentication', 'cvssV2_confidentialityImpact', 
    'cvssV2_integrityImpact', 'cvssV2_availabilityImpact', 'cvssV2_baseScore', 'baseMetricV2_severity', 'baseMetricV2_exploitabilityScore', 'baseMetricV2_impactScore', 'baseMetricV2_acInsufInfo', 'baseMetricV2_obtainAllPrivilege', 'baseMetricV2_obtainUserPrivilege', 'baseMetricV2_obtainOtherPrivilege', 
    'baseMetricV2_userInteractionRequired', 'publishedDate', 'lastModifiedDate']
    
    combined_csv_columns = ['key_4','key_5','key_6','key_7','key_8','key_9','key_11','key_12','key_14','key_17',
                            'key_28','key_29','key_30','key_31','key_32','key_33','key_34','key_35','key_36','key_37',
                            'key_38','key_39','key_40', 'key_41','key_42','key_43','key_44','key_45','key_46','key_47',
                            'key_48','key_49','key_50','key_51','key_52','key_53','key_54','key_55','key_56','key_57',
                            'key_58','key_59','key_60']
    
    
    dict_list = []
    combined_dict_list = []
    
    #for every vulnerability in the dataset create a new record
    for each_vulnerability in range(limit_download):             
                   
        print("\nLOG:","Working on Vulnerability #",each_vulnerability)
        try:
            #this dictionary will be used to store the attributes of each vulnerability    
            row_values_dict = {}
            
            #for each of the 60 attributes of do the following
            for item in range(60):
                #print("\nLOG:","Working on attribute #",item + 1,"for Vulenrability #",each_vulnerability + 1)
                
                i=item
                            
                #After flattening the JSON file, the Data dictionary created unique key names for each vulnerability,
                #thus have to create so many variables! 
                #note - some key names depend on the value of 'each_vulnerability'                        
                key_1 = 'CVE_data_type'  
                key_2 ='CVE_data_format' 
                key_3 ='CVE_data_version' 
                key_4 = 'CVE_data_timestamp'  
                key_5 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_data_type'  
                key_6 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_data_format'  
                key_7 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_data_version'  
                key_8 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_CVE_data_meta_ID'  
                key_9 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_CVE_data_meta_ASSIGNER'  
                #key_10 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_problemtype_problemtype_data_0_description_0_lang'  
                
                key_11 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_problemtype_problemtype_data_0_description_0_value'
                key_11b = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_problemtype_problemtype_data_0_description_value'
                
                key_12 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_references_reference_data_0_url'  
                key_13 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_references_reference_data_0_name'  
                key_14 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_references_reference_data_0_refsource'  
                #key_15 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_references_reference_data_0_tags_0'  
                key_16 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_description_description_data_0_lang'  
                key_17 = 'CVE_Items_{}'.format(each_vulnerability) + '_cve_description_description_data_0_value'  
                key_18 = 'CVE_Items_{}'.format(each_vulnerability) + '_configurations_CVE_data_version'  
                key_19 = 'CVE_Items_{}'.format(each_vulnerability) + '_configurations_nodes_0_operator'  
                #key_20 = 'CVE_Items_{}'.format(each_vulnerability) + '_configurations_nodes_0_cpe_match_0_vulnerable'  
                
                #key_21 = 'CVE_Items_{}'.format(each_vulnerability) + '_configurations_nodes_0_cpe_match_0_cpe23Uri'  
                #key_22 = 'CVE_Items_{}'.format(each_vulnerability) + '_configurations_nodes_0_cpe_match_1_vulnerable'  
                #key_23 = 'CVE_Items_{}'.format(each_vulnerability) + '_configurations_nodes_0_cpe_match_1_cpe23Uri'  
                #key_24 = 'CVE_Items_{}'.format(each_vulnerability) + '_configurations_nodes_0_cpe_match_2_vulnerable'  
                #key_25 = 'CVE_Items_{}'.format(each_vulnerability) + '_configurations_nodes_0_cpe_match_2_cpe23Uri'  
                #key_26 = 'CVE_Items_{}'.format(each_vulnerability) + '_configurations_nodes_0_cpe_match_3_vulnerable'  
                #key_27 = 'CVE_Items_{}'.format(each_vulnerability) + '_configurations_nodes_0_cpe_match_3_cpe23Uri'  
                key_28 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_version'  
                key_29 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_vectorString'  
                key_30 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_attackVector'  
                
                key_31 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_attackComplexity'  
                key_32 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_privilegesRequired'  
                key_33 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_userInteraction'  
                key_34 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_scope'  
                key_35 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_confidentialityImpact'  
                key_36 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_integrityImpact'  
                key_37 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_availabilityImpact'  
                key_38 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_baseScore'  
                key_39 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_cvssV3_baseSeverity'  
                key_40 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_exploitabilityScore'  
                
                key_41 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV3_impactScore'  
                key_42 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_cvssV2_version'  
                key_43 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_cvssV2_vectorString'  
                key_44 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_cvssV2_accessVector'  
                key_45 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_cvssV2_accessComplexity'  
                key_46 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_cvssV2_authentication'  
                key_47 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_cvssV2_confidentialityImpact'  
                key_48 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_cvssV2_integrityImpact'  
                key_49 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_cvssV2_availabilityImpact'  
                key_50 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_cvssV2_baseScore'  
                
                key_51 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_severity'  
                key_52 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_exploitabilityScore'  
                key_53 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_impactScore'  
                key_54 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_acInsufInfo'  
                key_55 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_obtainAllPrivilege'  
                key_56 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_obtainUserPrivilege'  
                key_57 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_obtainOtherPrivilege'  
                key_58 = 'CVE_Items_{}'.format(each_vulnerability) + '_impact_baseMetricV2_userInteractionRequired'  
                key_59 = 'CVE_Items_{}'.format(each_vulnerability) + '_publishedDate'  
                key_60 = 'CVE_Items_{}'.format(each_vulnerability) + '_lastModifiedDate'  
                                    
                i +=1
                new_key = 'key_{}'.format(i)  
                
                #python has no in-built switch! :O
                #deal with these if statements! It's just switching between keys made above
                if item == 0:                
                    try: row_values_dict[new_key] = dict_data[key_1]
                    except: row_values_dict[new_key] = ' '
                elif item == 1:
                    try: row_values_dict[new_key] = dict_data[key_2]
                    except: row_values_dict[new_key] = ' '
                elif item == 2:
                    try: row_values_dict[new_key] = dict_data[key_3]
                    except: row_values_dict[new_key] = ' '
                elif item == 3:
                    try: row_values_dict[new_key] = dict_data[key_4]
                    except: row_values_dict[new_key] = ' '
                elif item == 4:
                    try: row_values_dict[new_key] = dict_data[key_5]
                    except: row_values_dict[new_key] = ' '
                elif item == 5:
                    try: row_values_dict[new_key] = dict_data[key_6]
                    except: row_values_dict[new_key] = ' '
                elif item == 6:
                    try: row_values_dict[new_key] = dict_data[key_7]
                    except: row_values_dict[new_key] = ' '
                elif item == 7:
                    try: row_values_dict[new_key] = dict_data[key_8]
                    except: row_values_dict[new_key] = ' '
                elif item == 8:
                    try: row_values_dict[new_key] = dict_data[key_9]
                    except: row_values_dict[new_key] = ' '
                elif item == 9:
                    row_values_dict[new_key] = ' ' #not all vulnerabilities have this field populated            
                elif item == 10:
                    try:
                        row_values_dict[new_key] = dict_data[key_11]
                    except:
                        try:
                            row_values_dict[new_key] = dict_data[key_11b] #try an alternate key
                        except:
                            row_values_dict[new_key] = '' #not all vulnerabilities have this field populated
                elif item == 11:
                    try: row_values_dict[new_key] = dict_data[key_12]
                    except: row_values_dict[new_key] = ' '
                elif item == 12:
                    try: row_values_dict[new_key] = dict_data[key_13]
                    except: row_values_dict[new_key] = ' '
                elif item == 13:
                    try: row_values_dict[new_key] = dict_data[key_14]
                    except: row_values_dict[new_key] = ' '
                elif item == 14:
                    row_values_dict[new_key] = ' ' #not all vulnerabilities have this field populated
                elif item == 15:
                    try: row_values_dict[new_key] = dict_data[key_16]
                    except: row_values_dict[new_key] = ' '
                elif item == 16:
                    try: row_values_dict[new_key] = dict_data[key_17]
                    except: row_values_dict[new_key] = ' '
                elif item == 17:
                    try: row_values_dict[new_key] = dict_data[key_18]
                    except: row_values_dict[new_key] = ' '
                elif item == 18:
                    try: row_values_dict[new_key] = dict_data[key_19]
                    except: row_values_dict[new_key] = ' '
                elif item == 19:
                    row_values_dict[new_key] = ' ' #not all vulnerabilities have this field populated
                elif item == 20:
                    row_values_dict[new_key] = ' ' #not all vulnerabilities have this field populated
                elif item == 21:
                    row_values_dict[new_key] = ' ' #not all vulberabilities have multiple of this item
                elif item == 22:
                    row_values_dict[new_key] = ' ' #not all vulberabilities have multiple of this item
                elif item == 23:
                    row_values_dict[new_key] = ' ' #not all vulberabilities have multiple of this item
                elif item == 24:
                    row_values_dict[new_key] = ' ' #not all vulberabilities have multiple of this item
                elif item == 25:
                    row_values_dict[new_key] = ' '#not all vulberabilities have multiple of this item
                elif item == 26:
                    row_values_dict[new_key] = ' ' #not all vulberabilities have multiple of this item
                elif item == 27:
                    try:
                        row_values_dict[new_key] = dict_data[key_28] #not all vulnerabilities have this field populated
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 28:
                    try:
                        row_values_dict[new_key] = dict_data[key_29] #not all vulnerabilities have this field populated           
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 29:
                    try:                    
                        row_values_dict[new_key] = dict_data[key_30] #not all vulnerabilities have this field populated
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 30:
                    try:
                        row_values_dict[new_key] = dict_data[key_31] #not all vulnerabilities have this field populated
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 31:
                    try:
                        row_values_dict[new_key] = dict_data[key_32] #not all vulnerabilities have this field populated
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 32:
                    try:
                        row_values_dict[new_key] = dict_data[key_33]
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 33:
                    try:
                        row_values_dict[new_key] = dict_data[key_34] #not all vulnerabilities have this field populated
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 34:
                    try:
                        row_values_dict[new_key] = dict_data[key_35]
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 35:
                    try:
                        row_values_dict[new_key] = dict_data[key_36]
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 36:
                    try:
                        row_values_dict[new_key] = dict_data[key_37]
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 37:
                    try:
                        row_values_dict[new_key] = dict_data[key_38]
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 38:
                    try:
                        row_values_dict[new_key] = dict_data[key_39]
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 39:
                    try:
                        row_values_dict[new_key] = dict_data[key_40]
                    except:
                        row_values_dict[new_key] = ' '
                
                elif item == 40:
                    try:
                        row_values_dict[new_key] = dict_data[key_41]
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 41:
                    try:
                        row_values_dict[new_key] = dict_data[key_42]
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 42:
                    try:
                        row_values_dict[new_key] = dict_data[key_43]
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 43:
                    try: 
                        row_values_dict[new_key] = dict_data[key_44]
                    except:
                        row_values_dict[new_key] = ' '
                elif item == 44:
                    try: row_values_dict[new_key] = dict_data[key_45]
                    except: row_values_dict[new_key] = ' '
                elif item == 45:
                    try: row_values_dict[new_key] = dict_data[key_46]
                    except: row_values_dict[new_key] = ' '
                elif item == 46:
                    try: row_values_dict[new_key] = dict_data[key_47]
                    except: row_values_dict[new_key] = ' '
                elif item == 47:
                    try: row_values_dict[new_key] = dict_data[key_48]
                    except: row_values_dict[new_key] = ' '
                elif item == 48:
                    try: row_values_dict[new_key] = dict_data[key_49]
                    except: row_values_dict[new_key] = ' '
                elif item == 49:
                    try:row_values_dict[new_key] = dict_data[key_50]
                    except: row_values_dict[new_key] = ' '
                elif item == 50:
                    try: row_values_dict[new_key] = dict_data[key_51]
                    except: row_values_dict[new_key] = ' '
                elif item == 51:
                    try: row_values_dict[new_key] = dict_data[key_52]
                    except: row_values_dict[new_key] = ' '
                elif item == 52:
                    try: row_values_dict[new_key] = dict_data[key_53]
                    except: row_values_dict[new_key] = ' '
                elif item == 53:
                    try: row_values_dict[new_key] = dict_data[key_54]
                    except: row_values_dict[new_key] = ' '
                elif item == 54:
                    try: row_values_dict[new_key] = dict_data[key_55]
                    except: row_values_dict[new_key] = ' '
                elif item == 55:
                    try: row_values_dict[new_key] = dict_data[key_56]
                    except: row_values_dict[new_key] = ' '
                elif item == 56:
                    try: row_values_dict[new_key] = dict_data[key_57]
                    except: row_values_dict[new_key] = ' '
                elif item == 57:
                    try: row_values_dict[new_key] = dict_data[key_58]
                    except: row_values_dict[new_key] = ' '
                elif item == 58:
                    try: row_values_dict[new_key] = dict_data[key_59]
                    except: row_values_dict[new_key] = ' '
                elif item == 59:
                    try: row_values_dict[new_key] = dict_data[key_60]
                    except: row_values_dict[new_key] = ' '
                else:
                    try: row_values_dict[new_key] = dict_data[key_1]
                    except: row_values_dict[new_key] = ' '
        
                #row_values_dict[new_key] = dict_data["%key_1"]            
                
                #print("LOG: Attribute",item + 1,"for Vulnerability ID#",dict_data[key_8],"is complete!")
        except:
            print("FAIL")
        try:
            if dict_data[key_8]:
                dict_list.append(row_values_dict)
        except:
            print("ERROR: Could not find vulnerability details. Moving on.")
        print("SUCCESS: Vulnerability ID#",each_vulnerability + 1,"is complete!")
        
        try:
            print("Combining")
            combined_dict_list_dict = { key:value for key,value in row_values_dict.items() if key in combined_csv_columns}       
            combined_dict_list.append(combined_dict_list_dict)
            print("Combine complete")
        except:
            print("Combine FAILED. Moving on.")
    #create an individual csv file
    try:
        #create an empty file with only headers
        with open(csv_file, 'w+', newline='') as outcsv:
            writer = csv.writer(outcsv)
            writer.writerow(csv_columns_headers)      
            print("\nLOG: Headers have been created")
        #for every vulnerability in the dataset create a new row
        with open(csv_file, 'a+', encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns, lineterminator = '\n')
            #writer.writerow(csv_columns_headers)
            #writer.writeheader()
            for data in dict_list:
                writer.writerow(data)
        print("\nSUCCESS: Data loaded into CSV! Woot! Woot!")
                
    except IOError:
        print("FAIL: I/O error: The file maybe left open.")
                    
    #create a combined csv file    
    try:
        if not path.exists(combined_csv):
             with open(combined_csv, 'w+', newline='') as combined_outcsv_header:
                writer = csv.writer(combined_outcsv_header)
                print("File doesn't exist, creating file with headers")
                writer.writerow(combined_csv_columns_headers)
        #create an empty file with only headers
        with open(combined_csv, 'a+', newline='') as combined_outcsv:
            writer = csv.writer(combined_outcsv)
            #if not path.exists(combined_csv):
            #    writer.writerow(combined_csv_columns_headers)      
            print("\nLOG: Headers have been created")
        #for every vulnerability in the dataset create a new row
        with open(combined_csv, 'a+', encoding="utf-8") as combined_csvfile:
            writer = csv.DictWriter(combined_csvfile, fieldnames=combined_csv_columns, lineterminator = '\n')
            #writer.writerow(csv_columns_headers)
            #writer.writeheader()
            for data in combined_dict_list:
                if data:
                    writer.writerow(data)
                else:
                    print("Empty record - ignoring")
        print("\nSUCCESS: Data loaded into CSV! Woot! Woot!")
                
    except IOError:
        print("FAIL: I/O error: The file maybe left open.")
        
#Start of data scraping functions for exploit-vulnerability mapping
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
        
    with open("temp/exploit_vuln_mapping.pickle","wb") as f:
        pickle.dump(tickers,f)
    
    print("\nSUCCESS: Series List of vulnerabilities fetched!\n")  

    print("Dictionary", tickers_dict)      
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
 
#End of data scraping functions for exploit-vulnerability mapping
    
def load_contents_to_CSV(dictionary_contents, mapping_outputfile_name):
    with open(mapping_outputfile_name, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Exploit_ID","List_of_Vulnerabilities"])
    
    for exploit,vulnerability in dictionary_contents.items() :     
        #print the elements being loaded into the output file       
        print("Exploit::",exploit,
              "List_of_Vaulnerabilities::",vulnerability  
              )
    
        #Load into a CSV file
        with open(mapping_outputfile_name, 'a+', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([exploit,vulnerability])
            
#Main Program
print("Welcome to the Backend for our Group Project\n")
print("This is a project by GROUP 8 for the 'Advanced Program in Data Science' at IIM-C, Batch #3'\n")

#Warnings ignored!
#warnings.filterwarnings("ignore") # I am badass like that

print("Let's begin, at the moment __name__ has the default value of:", __name__)
    
def main():
    print("python main function")
    
    #Limit to 500 vulnerabilities for each year, for the purpose of testing
    limit_download = 25000
    
    #final output file name
    combined_csv = "output/CVSS_Last20_years_combined.csv"
    mapping_outputfile_name = "output/CVSS_Exploit_Mapping.csv"
    
    #range of years to download
    start_year = 2015 #earliest year available for dowload is 2015
    end_year = 2020   #at the moment, latest year can be 2020
    
    print("\nJust for fun, we shall work our way backwards, starting from year",end_year,"to",start_year,"!!")
    
    for year in reversed(range(start_year,end_year+1,1)):   
      
        print("\nWorking on year",year)
        
        #enter the filenames, urls etc   
        json_download_filename = 'downloads/nvdcve-1.1-{}'.format(year)+'.json'
        zipped_filename = 'downloads/vulnerabilities_{}'.format(year)+'.zip'
        download_from_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}'.format(year)+'.json.zip'        
        output_file_name = 'output/CVSS_vulnerability_list_{}'.format(year)+'.csv'
        
        #download from URL
        download_zip_from_url(download_from_url, zipped_filename)
        #unip the file
        unzip_file(zipped_filename)
        #combine all the downloaded files
        #combine_json()
        
        #Convert the JSON file to CSV
        convert_JSON_to_CSV(json_download_filename, output_file_name, combined_csv, limit_download)
        
    try:
        print("Data Source#2: This contains the mapping between Vulnerabilities and Exploits\nLet the web data scrapping begin!\n")      
        APDS_mapping_download_code.exploit_mapping_download()
        print("SUCCESS: The data has been scraped: Exploit-Vulnerability mapping ready!")        
    except:
        print("ERROR: That failed. Didn't manage to download the exploits!\n")       
              
if __name__ == '__main__':
    main() 
   