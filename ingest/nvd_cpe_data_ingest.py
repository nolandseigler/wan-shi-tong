import datetime
import json
import os
from pathlib import Path

# import pytz
import requests
from requests.exceptions import HTTPError
import time
import zipfile

from config import project_root
from db.database import CVE
from env_vars import cpe_data_dir

"""
This module is used to download the initial NVD Data Feeds required for the app and write those to a Postgres DB.
Steps:
1. Download the ZIP files.
2. Extract CVEs from data files and format into record format.
3. Write records to db.
4. Delete the ZIP files.
"""


def download_cpe_match_json_zip():
    """
    Data is from NIST National Vulnerability Database
    Download format is .zip
    https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip
    """
    download_url = (
        "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip"
    )

    # Make cve data download dir if not exists
    if not cpe_data_dir.is_dir():
        print(
            f"'nvd_cve_data directory' at {cpe_data_dir} is not present.\n Commencing full cpe zip download."
        )
        os.mkdir(cpe_data_dir)

    zip_file_name = "nvdcpematch-1.0.json.zip"
    zip_file_path = cpe_data_dir / zip_file_name

    # only download if the file does not exist
    if not zip_file_path.is_file():
        print(f"Downloading zip file from '{download_url}'")
        response = requests.get(download_url, allow_redirects=True)
        open(f"{zip_file_path}", "wb").write(response.content)
    else:
        print(
            f"'{download_url}' has already been downloaded.\n File is located at '{zip_file_path}'"
        )

    print("Zip file download complete.")


def download_cpe_dictionary_xml_zip():
    """
    Data is from NIST National Vulnerability Database
    Download format is .zip
    https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
    """
    download_url = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"

    # Make cve data download dir if not exists
    if not cpe_data_dir.is_dir():
        print(
            f"'nvd_cve_data directory' at {cpe_data_dir} is not present.\n Commencing full cpe zip download."
        )
        os.mkdir(cpe_data_dir)

    zip_file_name = "official-cpe-dictionary_v2.3.xml.zip"
    zip_file_path = cpe_data_dir / zip_file_name

    # only download if the file does not exist
    if not zip_file_path.is_file():
        print(f"Downloading zip file from '{download_url}'")
        response = requests.get(download_url, allow_redirects=True)
        open(f"{zip_file_path}", "wb").write(response.content)
    else:
        print(
            f"'{download_url}' has already been downloaded.\n File is located at '{zip_file_path}'"
        )

    print("Zip file download complete.")


def extract_zip(zip_file_path, directory_to_extract_to):
    with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
        zip_ref.extractall(directory_to_extract_to)
    unzipped_file_name_str = str(zip_file_path).replace(".zip", "")
    return Path(unzipped_file_name_str)


def write_cpe_match_json_to_db(cpe_match_json_zip_file_path):
    """
    Write all cpe match records in a json file to db and delete JSON file.
    This is okay because we currently maintain the zip file.
    """
    unzipped_file_path = extract_zip(cpe_match_json_zip_file_path, cpe_data_dir)

    with open(unzipped_file_path) as json_file:
        cpe_data = json.load(json_file)

    for match_object in cpe_data["matches"]:
        if match_object["cpe_name"]:
            cpe_name = ",".join(match_object["cpe_name"])
        else:
            cpe_name = None

        cpe_match_to_write = CPE_Match(
            cpe_23_uri=match_object["cpe23Uri"],
            cpe_name=cpe_name,
            full_cpe_match_json=match_object,
        )
        cpe_match_to_write.save()

    os.remove(unzipped_file_path)


# def write_all_cve_json_zip_to_db():
#     """
#     Searches cve_data directory for all files with .json.zip in file name.
#     For each file found it extracts the .zip, opens file, reads in json, parses json to create CVE object, writes CVE object as record in cve table.
#     """
#     if not CVE.query.limit(1).all():
#         print("Writing initial CVEs to db from zip.")
#         current_year = int(datetime.date.today().strftime("%Y"))
#         # write records for each cve in each yearly cve zip
#         for year in range(2002, current_year+1):
#             zip_file_name = f"nvdcve-1.1-{year}.json.zip"
#             zip_file_path = cve_data_dir / zip_file_name

#             # extracts zip to json and writes cves to db
#             write_cve_json_to_db(cve_json_zip_file_path=zip_file_path)
#     else:
#         print("CVE table has been hydrated with initial CVEs.")

# def download_and_hydrate_cve():
#     download_all_cve_json()
#     write_all_cve_json_zip_to_db()


# def is_cve_modified_feed_updated():
#     """
#     Checks if modified cve feed has been updated since our last pull of the modified feed.
#     Tasks:
#         - Download the meta file.
#         - Retrieve the value for key "lastModifiedDate"
#         - Convert that string to datetime.datetime
#         - Get the time our last modified zip was modified.
#             - os.path.getmtime(path)
#         - If lastModifedDate is more recent than our local files last mtime then return True
#         - Else return False

#     Download url for meta file:
#     https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta

#     Output: bool
#         True if update is required
#     """
#     base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"
#     meta_path = "nvdcve-1.1-modified.meta"

#     try:
#         response = requests.get(f"{base_url}/{meta_path}")
#         # If the response was successful, no Exception will be raised
#         response.raise_for_status()
#         response_text = response.text
#         # TODO: Find a better way to create a datetime.datetime
#         last_modified_split_list = response_text.split("\r")[0]
#         last_modified_split_1 = last_modified_split_list.split(":")[1].split("T")
#         last_modified_date_split = last_modified_split_1[0].split("-")
#         last_modified_year = last_modified_date_split[0]
#         last_modified_month = last_modified_date_split[1]
#         last_modified_day = last_modified_date_split[2]
#         last_modified_time = last_modified_split_1[1] + ":" + last_modified_split_list.split(":")[2]
#         last_modified_time_split = last_modified_time.split(":")
#         last_modified_hour = last_modified_time_split[0]
#         last_modified_minute = last_modified_time_split[1]

#         last_modified_datetime_obj = datetime.datetime(year=int(last_modified_year), month=int(last_modified_month), day=int(last_modified_day),
#         hour=int(last_modified_hour), minute=int(last_modified_minute))

#         # TODO: ^ Find a better way to create a datetime.datetime
#         # nvdcve-1.1-modified.json.zip
#         modified_cve_path = f"nvdcve-1.1-modified.json.zip"
#         download_url = f"{base_url}/{modified_cve_path}"

#         zip_file_name = modified_cve_path
#         zip_file_path = cve_data_dir / zip_file_name

#         if os.path.isfile(zip_file_path):
#             modified_zip_modified_time = datetime.datetime.fromtimestamp(os.path.getmtime(zip_file_path))
#             return last_modified_datetime_obj > modified_zip_modified_time
#         else:
#             return True

#     except HTTPError as http_err:
#         print(f'HTTP error occurred: {http_err}')
#     except Exception as err:
#         print(f'Other error occurred: {err}')


# def ensure_cve_modified_feed_is_updated():
#     """
#     If update is available:
#         download zip and write cves to cve table.
#     """
#     if is_cve_modified_feed_updated():
#         base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"
#         modified_cve_path = f"nvdcve-1.1-modified.json.zip"
#         download_url = f"{base_url}/{modified_cve_path}"

#         print(f"Downloading zip file from '{download_url}'")
#         response = requests.get(download_url, allow_redirects=True)
#         zip_file_path = cve_data_dir / modified_cve_path
#         open(f"{zip_file_path}", "wb").write(response.content)

#         write_cve_json_to_db(zip_file_path)
#     else:
#         print("CVE modified feed has not been updated since last download.")
