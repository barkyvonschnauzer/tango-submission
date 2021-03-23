import binascii
import csv
import datetime
import io
import iocextract
import json
import logging
import math
import os
import pandas as pd
import pytesseract
import requests
import time


from azure.cosmos import CosmosClient
from collections import Counter
from datetime import datetime
from dateutil.relativedelta import relativedelta
from pathlib import Path
from PIL import Image
from urlextract import URLExtract


####################
# GLOBAL VARIABLES #
####################

MAX_POST_REQ_NETCRAFT = 1000 

# Supported file types
img_exts = ['jpg', 'png', 'gif', 'bmp', 'tiff']
doc_exts = ['txt', 'csv', 'doc', 'rtf']

##########################################################################
#
# Function name: main
# Input: Blob that triggered this function to be run.
# Output: TBD
#
# Purpose: Extract and action reported URLs for categorization.
#
##########################################################################
def main():

    input_file = Path('/input') / os.environ.get('INPUT_FILE')
    print (input_file)

    if input_file:
        # Extract URLs from blob and dedup
        file_content    = access_input_file(input_file)
        url_list        = extract_URLs(file_content)
        unique_url_list = dedup_URLs(url_list)
        urls_to_submit  = check_urls(unique_url_list)

        print("\n***** URLs sent to Netcraft *****")
        for url in urls_to_submit:
            print (url)

        # Send list of deduped (unique) URLs to Netcraft for assessment
        #num_calls_netcraft = math.ceil((len(unique_url_list))/MAX_POST_REQ_NETCRAFT)
        #netcraft_uuids = []

        #for j in range(num_calls_netcraft):
        # Check list of URLs againts Netcraft
        #list_subset_netcraft = unique_url_list[j*MAX_POST_REQ_NETCRAFT:(MAX_POST_REQ_NETCRAFT*(1 + j))]
        if len(urls_to_submit) > 0:
            uuid = submit_URLs_Netcraft(urls_to_submit)
            print ("Netcraft UUID: " + uuid)
            #netcraft_uuids.append(uuid)

            if uuid == "0000":
                print ("Error, UUID is set to default value of 0000\n")
            else:
                update_cosmos_db(uuid, len(url_list), len(urls_to_submit), urls_to_submit)
        else:
            print ("No new URLs to submit to Netcraft")

        # store volumes for all URLs received in DB
        store_url_counts(url_list, unique_url_list)

    else:
        print ("Input file not found")


##########################################################################
#
# Function name: store_url_counts
# Input: url_list
# Output: TBD
#
# Purpose: update the db to include information on urls received:
#          - date/time
#          - url
#          - number of submissions
#
##########################################################################
def store_url_counts(url_list, unique_url_list):

    print ("**** COUNT URLS ****\n")
    print(url_list)
    url_counts = dict(Counter(url_list))
    print(url_counts)

    uri          = os.environ.get('ACCOUNT_URI')
    key          = os.environ.get('ACCOUNT_KEY')
    database_id  = os.environ.get('DATABASE_ID')
    container_id = os.environ.get('URL_CONTAINER_ID')

    client    = CosmosClient(uri, {'masterKey': key})
    database  = client.get_database_client(database_id)
    container = database.get_container_client(container_id)

    date_str    = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    id_date     = int((datetime.utcnow()).timestamp())
    id_date_str = str(id_date)

    output = []
    for k,v in url_counts.items():
        output.append({'url':k, 'count':v})

    container.upsert_item({'id': id_date_str,
                           'date_time': id_date_str,
                           'date': date_str,
                           'urls_and_counts': output})


##########################################################################
#
# Function name: check_urls
# Input: unique_url_list
# Output: list of urls that have not been submitted in the past 24 hours.
#
# Purpose: identify which of the most-recently received URLs have not 
#          been submitted ot Netcraft in the past 24 hours.
#
##########################################################################
def check_urls(url_list):

    print ("**** CHECK URLS ****\n")

    uri          = os.environ.get('ACCOUNT_URI')
    key          = os.environ.get('ACCOUNT_KEY')
    database_id  = os.environ.get('DATABASE_ID')
    container_id = os.environ.get('CONTAINER_ID')

    reported_urls = []

    client    = CosmosClient(uri, {'masterKey': key})
    database  = client.get_database_client(database_id)
    container = database.get_container_client(container_id)

    print ("Query db for UUIDs since yesterday\n")

    yesterday  = int((datetime.utcnow() - relativedelta(days=1)).timestamp())

    query = 'SELECT c.urls_unq FROM c WHERE c._ts > {}'.format(str(yesterday))
    url_results = list(container.query_items(query, enable_cross_partition_query = True))

    for record in url_results:
        record_urls = (record['urls_unq'].split(' '))
        reported_urls.extend(record_urls)

    print ("Previously Reported URLs")
    print (reported_urls)
    print ("\nNewly Reported URLs")
    print (url_list)

    # identify which urls are being submitted for the first time in 24 hours
    new_unique_urls = list(set(url_list) - set(reported_urls))

    print ("\nURLs to report to Netcraft")
    print (new_unique_urls)

    return new_unique_urls

#########################################################################
#
# Function name: access_input_file
# Input: name of inout file
# Output: Returns the content of the file.
#
# Purpose: determine the file type, extract the content and prepare for
#          URL extraction.
#
##########################################################################
def access_input_file(input_file):

    print ("\n***** access_input_file *****\n")

    ### Determine the file type ###
    extension = os.path.splitext(input_file.name)[1][1:]

    if extension in img_exts:
        ### Open image ###
        input_image = input_file
        screen_image = Image.open(input_image)

        ### Perform image-to-text conversion ###
        ### Python-tesseract is a wrapper for Google's Tesseract-OCR Engine.
        content = pytesseract.image_to_string(screen_image)
    elif extension in doc_exts:
        ### Read text content of csv file ###
        fp = open(input_file, 'r')
        content= fp.read()
        fp.close()

    else:
        print ("Unable to process blob.  File type has not been explicitly stated as part of the file name and/or is not supported.")
        content = None

    print ("Successfully accessed blob")

    return content


##########################################################################
#
# Function name: extract_URLs
# Input: content (text)
# Output: non-deduped, non-sorted list of extracted URLs and IPs.
#
# Purpose: identify and extract the URLs and IPs present in the text input.
#
##########################################################################
def extract_URLs(content):

    if content is not None:
        print ("\n***** Extract URLs *****\n")
        ### Identify URLs in content ###

        extractor = URLExtract();
        extractor_urls  = extractor.find_urls(content)
        
        iocextract_urls = list(iocextract.extract_urls(content, refang=True))
        iocextract_ips  = list(iocextract.extract_ips(content, refang=True))

        iocextract_ips_valid = []

        if (len(iocextract_ips) > 0):
            for ip in iocextract_ips:
                # Add check to further refine list of potential IPs:
                # Basic format check: 
                #     IPv4: xxx.xxx.xxx.xxx or
                #     IPv6: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
                if ip.count(".") != 3 or ip.count(":") != 7:
                    print ("Invalid IP address: " + str(ip))
                else:
                    iocextract_ips_valid.append(ip)
        
        print ("iocextract.extract_ips method - format validated")
        print (iocextract_ips_valid)
        print ("extractor.find method")
        print (extractor_urls)
        print ("iocextract.extract_urls method")
        print (iocextract_urls)

        info_to_evaluate = extractor_urls + iocextract_urls + iocextract_ips_valid

        index = 0

        # Occassionally, the functions above return urls with trailing commas.  Remove these.
        for ioc in info_to_evaluate:
            if ioc.endswith(','):
                info_to_evaluate[index] = ioc[:-1]
            index += 1

        print ("Removed trailing commas")
        print (info_to_evaluate)

        print ("Successfully extracted URLs")

        return info_to_evaluate


##########################################################################
#
# Function name: dedup_URLs
# Input: list of URLs
# Output: deduped list of URLs
#
# Purpose: produce a deduped list of URLs extracted from the blob 
#          processed.
#
##########################################################################
def dedup_URLs(url_list):

    print ("\n***** De-duping URL list *****\n")

    unique_url_list = list();

    if url_list is not None:
        unique_url_list = list(set(url_list))

    print ("Successfull de-duped URL list")

    print ("Initially Deduped list")
    print (unique_url_list)

    return unique_url_list

##########################################################################
#
# Function name: submit_URLs_Netcraft
# Input: Unique list of IPs
# Output: Returns the result of submitting the url(s) to netcraft:
#         - return_string: string describing success/failure of operation
#         - uuid: if call was successful, uuis should be non-zero.  Else, 
#           populated with "0000"
#         - state: the state of the request
#        
#
# Purpose: Submit list of unique URLs for processing with Netcraft.
#

##########################################################################
def submit_URLs_Netcraft(unique_url_list):

    print("\n***** Submit extracted URLs to Netcraft for evaluation *****\n")

    # The below link is for development.  Once deployed, use:
    netcraftReport_url = "https://report.netcraft.com/api/v3/report/urls"

    headers = {'Content-type': 'application/json'}

    request_data = {
        "email": "karen.vanderwerf@cyber.gc.ca",
        "urls": [{"url": u} for u in unique_url_list],#[u for u in unique_url_list],
        }

    # Check URLs with netcraft service
    r_post = requests.post(netcraftReport_url, json=request_data, headers=headers)

    print("Netcraft Report URLs response status code: " + str(r_post.status_code))
    print(r_post.json())

    #state = {}
    uuid = "0000"

    # Update SQL db table entries where url is in unique_url_list with the uuid returned

    if r_post.status_code == 200:
        uuid = r_post.json()['uuid']
        print("UUID: " + str(uuid))
        #state = check_URLs_state_Netcraft_bulk(uuid, unique_url_list)
        return_string = "success"
    elif r_post.status_code == 400:
        # A number of different reasons could have caused this return code:
        # 1 - a single incorrectly formatted url
        # 2 - submission is an exact duplicate of a previous request
        # ... to add more as they come up ...
        response = r_post.json()
        #print(response)

        #print("**** ALL ****")
        #for all_url in unique_url_list:
        #    print(all_url)

        for field in response["details"]:
            print(field)
            if field["message"]:
                if "Duplicate" in field["message"]:
                    print("Duplicate Error")
                    return_string = "duplicate"

                if "Does not match url format" in field["message"]:
                    print("URL Formatting Error")
                    # Get the offending entries:
                    if field["input"]:
                        print(field["input"])
                        bad_url = field["input"]

                        print("Remove " + bad_url + " from list")
                        unique_url_list.remove(bad_url)

                    return_string = "formatting error"

                state = {}

        #print("**** GOOD ****")
        #for good_url in unique_url_list:
        #    print(good_url)

        if return_string == "formatting error" and len(unique_url_list) > 0:
            # resubmit the list with the poorly formatted URLs removed
            print("Resubmitting valid URLs")
            uuid = submit_URLs_Netcraft(unique_url_list)

    # Other possible error codes: 429 - too many submissions
    #else: 
    #    state = {}

    return uuid

##########################################################################
#
# Function name: check_URLs_state_Netcraft_bulk
# Input: uuid returned from Netcraft submission,
#        list of unique urls submitted to Netcraft for processing
#
# Output:
#
# Purpose: to check the characterization of each URL submitted to 
#          Netcraft.  
#          Possible results:
#          (v2)
#          - processing
#          - no threats
#          - unavailable
#          - phishing
#          - already blocked
#          - suspicious
#          - malware
#          - rejected (was already submitted)
#          (v3)
#          - processing
#          - no threats
#          - unavailable
#          - malicious
#          - suspicious
#
##########################################################################
def check_URLs_state_Netcraft_bulk(uuid, unique_url_list):

    print("\n***** Query Netcraft for URL classification by UUID *****\n")

    uuid_str = str(uuid)

    # submit GET request to Netcraft for each UUID identified above
    # The below link is for development.  Once deployed, use:
    netcraftSubmissionCheck_url = "https://report.netcraft.com/api/v3/submission/" + uuid_str + "/urls"

    # Check URLs with netcraft service
    headers = {'Content-type': 'application/json'}
    result = {}
    request_data = {};

    # Check URLs with netcraft service
    r_get = requests.get(netcraftSubmissionCheck_url, json=request_data, headers=headers)

    print("Netcraft submission check response status code (" + uuid_str + "): " + str(r_get.status_code))
    print(r_get.json())

    if r_get.status_code == 200:
        if r_get.json() == {}:
            print("No results available.")

        else:
            print("Results for uuid:", uuid_str, " available.")
            # Get results
            for entry in r_get.json()['urls']:
                print(entry)
                url = entry['url']
                url_state = entry['url_state']
                print ("url: ", url)
                print ("url state: ", url_state)

                if url_state in ["malicious", "suspicious"]: #v3
                #if url_state in ["phishing", "already blocked", "suspicious", "malware"]: #v2
                    print("Likely malicious")
                    result[url] = {
                        'malicious': True,
                        'threats': str(url_state)
                        }
                elif url_state == "no threats":
                    print("Likely safe")
                    result[url] = {
                        'malicious': False,
                        'threats': str(url_state)
                    }
                else:
                    # These the categorization of these threats is unknown (processing or unavailable).
                    # Add these to the list for continued testing.
                    print("Currently unknown")
                    result[url] = {
                        'malicious': False,
                        'threats': str(url_state)
                    }

    return result

##########################################################################
#
# Function name: update_cosmos_db
# Input: 
#    - list of uuids associated to report
#    - number of URLs reported via partner
#    - number of deduped URLs reported via partner
# Output: 
#
# Purpose: Add record of uuid.
#
##########################################################################
def update_cosmos_db(uuid, num_urls_rec, num_urls_unq, unique_url_list):
    
    print ("\n***** Add UUID to the COSMOS DB *****\n")
    uri          = os.environ.get('ACCOUNT_URI')
    key          = os.environ.get('ACCOUNT_KEY')
    database_id  = os.environ.get('DATABASE_ID')
    container_id = os.environ.get('CONTAINER_ID')

    client    = CosmosClient(uri, {'masterKey': key})
    database  = client.get_database_client(database_id)
    container = database.get_container_client(container_id)

    # Get date
    date_str = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    all_uuid_str = uuid#' '.join(map(str, netcraft_uuids))

    #for uuid in netcraft_uuids:
    uuid_str = str(uuid)
    print (uuid_str)

    unique_url_list_str   = ' '.join(map(str, unique_url_list))

    print ("Informaton for new record: ")
    print ("    uuid: " + uuid_str)
    print ("    date: " + date_str)
    print ("    num URLs received: " + str(num_urls_rec))
    print ("    num unique URLs received: " + str(num_urls_unq))
    print ("    associated uuids: " + all_uuid_str)
    print ("    unique url list: " + unique_url_list_str)

    # information to include:
    # - uuid
    # - associated uuids
    # - date
    # - number of URLs received from partner
    # - number of unique URLs 
    # - number of valid URLs subitted to Netcraft
    # - list URLs received from client

    # statement to insert record
    container.upsert_item({ 'id': uuid_str,
                            'date': date_str,
                            'uuid': uuid_str,
                            'assoc_uuids': all_uuid_str,
                            'n_urls_in': num_urls_rec,
                            'n_urls_unq': num_urls_unq,
                            'urls_unq': unique_url_list_str })

if __name__ == "__main__":
    main()

