import datetime
import json
import os
from pathlib import Path
import requests
import time
import zipfile

from config import project_root
from db.database import CVE
from env_vars import cve_data_dir

"""
This module is used to download the initial NVD Data Feeds required for the app and write those to a Postgres DB.
Steps:
1. Download the ZIP files.
2. Extract CVEs from data files and format into record format.
3. Write records to db.
4. Delete the ZIP files.
"""

def download_all_cve_json():
    """
    Data is from NIST National Vulnerability Database
    Download format is .zip
    https://nvd.nist.gov/feeds/json/cve/1.1/<name_of_json_zip>
    """
    base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"

    # Make cve data download dir if not exists
    if not cve_data_dir.is_dir():
        print(f"'nvd_cve_data directory' at {cve_data_dir} is not present.\n Commencing full cve zip download.")
        os.mkdir(cve_data_dir)
    
    current_year = int(datetime.date.today().strftime("%Y"))
    # Download each yearly cve zip
    for year in range(2002, current_year+1):
        year_path = f"/nvdcve-1.1-{year}.json.zip"
        download_url = f"{base_url}{year_path}"

        zip_file_name = year_path.replace("/", "")
        zip_file_path = cve_data_dir / zip_file_name

        # only download if the file does not exist
        if not zip_file_path.is_file():
            print(f"Downloading zip file from '{download_url}'")
            response = requests.get(download_url, allow_redirects=True)
            open(f"{zip_file_path}", "wb").write(response.content)
            # Sleep for thirty seconds between requests because the api may rate limit us due to DDoS protections.
            time.sleep(30)
        else:
            print(f"'{download_url}' has already been downloaded.\n File is located at '{zip_file_path}'")

        print("Zip file download complete.")

def extract_zip(zip_file_path, directory_to_extract_to):
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(directory_to_extract_to)
    unzipped_file_name_str = str(zip_file_path).replace(".zip", "")
    return Path(unzipped_file_name_str)

def write_cve_json_to_db(cve_json_zip_file_path):
    """
    Write all cves in a json file to db and delete JSON file.
    This is okay because we currently maintain the zip file.
    """
    unzipped_file_path = extract_zip(cve_json_zip_file_path, cve_data_dir)

    with open(unzipped_file_path) as json_file:
        cve_data = json.load(json_file)

    for item in cve_data["CVE_Items"]:
        cve_item = item["cve"]
        cve_id = cve_item["CVE_data_meta"]["ID"]
        record_last_modified_date = item["lastModifiedDate"]

        # cve records are written from json zip files by year beginning with 2002 file(contains pre-2002 also) and ending with
        # the most recent json zip file from the current year.
        # this means that we will write multiple records for each cve if there are more than one.
        # for updates to prevent rewrites we check the last_modified_date and compare it to the most recent last_modified_date from table records
        # this ensures on initial hydration that all records are written but on updates multiple duplicate records are not ingested.
        db_cve = CVE.get_last_modified_record_by_cve_id(nvd_cve_id=cve_id)
        db_cve_last_modified_date = datetime.datetime.min
        if db_cve:
            db_cve_last_modified_date = db_cve.last_modified_date

        if record_last_modified_date > db_cve_last_modified_date:
            record_cve_id = cve_id
            record_description = cve_item["description"]["description_data"][0]["value"]
            # some older records do not have cvss v3 metrics
            if item["impact"].get("baseMetricV3"):
                record_cvss_v3_base_score = item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                record_cvss_v3_base_severity = item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                record_cvss_v3_impact_score = item["impact"]["baseMetricV3"]["impactScore"]
            else:
                record_cvss_v3_base_score = None
                record_cvss_v3_base_severity = None
                record_cvss_v3_impact_score = None

            if item["impact"].get("baseMetricV2"):
                record_cvss_v2_base_score = item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                record_cvss_v2_severity = item["impact"]["baseMetricV2"]["severity"]
                record_cvss_v2_impact_score = item["impact"]["baseMetricV2"]["impactScore"]
            else:
                record_cvss_v2_base_score = None
                record_cvss_v2_severity = None
                record_cvss_v2_impact_score = None

            record_published_date = item["publishedDate"]
            record_full_cve_json = item

            cve_to_write = CVE(
                cve_id = record_cve_id,
                description = record_description,
                cvss_v3_base_score = record_cvss_v3_base_score,
                cvss_v3_base_severity = record_cvss_v3_base_severity,
                cvss_v3_impact_score = record_cvss_v3_impact_score,
                cvss_v2_base_score = record_cvss_v2_base_score,
                cvss_v2_severity = record_cvss_v2_severity,
                cvss_v2_impact_score = record_cvss_v2_impact_score,
                published_date = record_published_date,
                last_modified_date = record_last_modified_date,
                full_cve_json = record_full_cve_json
            )
            cve_to_write.save()

    os.remove(unzipped_file_path)

def write_all_cve_json_zip_to_db():
    """
    Searches cve_data directory for all files with .json.zip in file name.
    For each file found it extracts the .zip, opens file, reads in json, parses json to create CVE object, writes CVE object as record in cve table.
    """
    if not CVE.query.limit(1).all():
        print("Writing initial CVEs to db from zip.")
        current_year = int(datetime.date.today().strftime("%Y"))
        # write records for each cve in each yearly cve zip
        for year in range(2002, current_year+1):
            zip_file_name = f"nvdcve-1.1-{year}.json.zip"
            zip_file_path = cve_data_dir / zip_file_name

            # extracts zip to json and writes cves to db
            write_cve_json_to_db(cve_json_zip_file_path=zip_file_path)
    else:
        print("CVE table has been hydrated with initial CVEs.")

def download_and_hydrate_cve():
    download_all_cve_json()
    write_all_cve_json_zip_to_db()

def ensure_modified_cve_json_is_updated():
    """
    download the meta file for the modified json cve feed.
    if lastModifiedDate > today:
        - remove old modified zip
        - download from modified feed
    """
    pass





