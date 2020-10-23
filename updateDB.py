#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

"""Vulnerability DB updater

Gets all feeds from NVD and aggregates all into a single DB.

NVD update timestamps are taken into consideration for selecting DB updates

"""

import requests
import re
import io
import zipfile
import json
import os
from datetime import datetime

nvd_base_url = "https://nvd.nist.gov"
nvd_data_feeds = f"{nvd_base_url}/vuln/data-feeds"
# downloads_folder = "tmp"

existing_dbs = "databases"
my_db = {}
if os.path.exists(existing_dbs):
    dbs = os.listdir(existing_dbs)
    # WIP
else:
    os.makedirs(existing_dbs)


# get feeds' url
all_feeds = requests.get(nvd_data_feeds)
my_feeds = re.findall(r'/feeds/json/cve/1.1/nvdcve-1.1-.*json.zip', all_feeds.text)

for feed in my_feeds:
    get_url = f'{nvd_base_url}{feed}'
    r = requests.get(get_url)
    z = zipfile.ZipFile(io.BytesIO(r.content))

    for filename in z.namelist():
        nvd_db = json.loads(z.read(filename))

    # z.extractall(downloads_folder)