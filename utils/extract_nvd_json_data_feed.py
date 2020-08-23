"""
This module is used to download the initial NVD Data Feeds required for the app and write those to a Postgres DB.
Steps:
1. Download the ZIP files.
2. Extract CVEs from data files and format into record format.
3. Write records to db.
4. Delete the ZIP files.
"""