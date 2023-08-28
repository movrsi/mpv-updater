#!/usr/bin/env python3

# This file is part of open-in-mpv.
#
# Copyright 2020 Andrew Udvare
# Copyright 2023 movrsi
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import logging
import re
import requests
import shutil
#import subprocess
import sys
import tempfile

import os

from hashlib import file_digest
from os.path import join
from string import hexdigits
from subprocess import check_output, Popen, PIPE
from typing import Dict, Final, List

API_MPV: Final[str] = "https://api.github.com/repos/shinchiro/mpv-winbuild-cmake/releases/latest"
API_YTDLP: Final[str] = "https://api.github.com/repos/yt-dlp/yt-dlp/releases/latest"
CRITERIA_YTDLP: Final[str] = "yt-dlp.exe"
CRITERIA_FFMPEG: Final[str] = r"ffmpeg\-x86\_64\-v3\-git\-[0-9a-f]{9}\.7z"
CRITERIA_MPV: Final[str] = r"^mpv\-x86\_64\-v3\-[0-9]{8}\-git\-[0-9a-f]{7}\.7z"
CRITERIA_SIG_FILE: Final[str] = 'open-in-mpv-updates'
FILES: Final[List[str]] = [
    "ffmpeg.exe", "mpv.exe", "yt-dlp.exe"
]
FILES_SEARCH: Final[List[str]] = [
    "ffmpeg-x86_64-git", "mpv-x86_64", CRITERIA_YTDLP
]
HASH_ALGORITHM: Final[str] = 'blake2b'
LOG: logging.Logger = logging.getLogger("mpv-updater-task")
TAR: Final[List[str]] = ['tar', '-xf']
HEADERS: Dict[str, str] = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
}

# Used to expose functions for unit testing.
__all__ = [
    'download_file', 'decompress', 'fetch_archives', 'find_files', 'find_signature_file',
    'hash_file_parse', 'hash_verify', 'process_active', 'process_terminate'
]

def download_file(path: str, url: str) -> str | None:
    filename: str = url.split('/')[-1]

    try:
        with requests.get(url, stream=True, headers=HEADERS) as r:
            with open(join(path, filename), 'wb') as f:
                shutil.copyfileobj(r.raw, f)
    except Exception:
        LOG.exception(f"Failed to download file from {url}.")
        return None
    
    return filename

def decompress(command: List[str], filepath: str) -> bool:
    command.append(filepath)
    process: Popen = Popen(command, stdout=PIPE, stderr=PIPE)
    command.remove(filepath)

    stdout: str = str(process.communicate()[0], "utf-8")
    stderr: str = str(process.communicate()[1], "utf-8")

    if len(stdout) > 0:
        LOG.info(stdout)
        
    if len(stderr) > 0:
        LOG.error(stderr)

    return process.returncode == 0

def fetch_archives() -> List[str]:
    ret: List[str] = []
    req = requests.get(API_MPV, headers=HEADERS)
    data = req.json()

    try:
        for asset in data['assets']:
            if re.match(CRITERIA_FFMPEG, asset['name']) or \
                  re.match(CRITERIA_MPV, asset['name']):
                ret.append(asset['browser_download_url'])
                LOG.info(f"mpv archive: {asset['name']}")
    except KeyError:
        LOG.exception(f"Failed to obtain package mpv from {API_MPV}")
        return ret
    
    req = requests.get(API_YTDLP, headers=HEADERS)
    data = req.json()

    try:
        for asset in data['assets']:
            if CRITERIA_YTDLP in asset['name']:
                 ret.append(asset['browser_download_url'])
    except KeyError as e:
        LOG.exception(f"Failed to obtain package {CRITERIA_YTDLP} from {API_YTDLP}")
        return ret
    
    # TODO signature file repository.
    return ret

def find_files(extension_filter: str, path: str) -> List[str]:
    ret: List[str] = []
    files: filter = filter(os.path.isfile, os.listdir(path))

    for file in files:
        try:
            if extension_filter in file.split(".")[1]:
                ret.append(file)
        except Exception:
            continue
        
    return ret

def find_signature_file(path: str) -> str | None:
    files: filter = filter(None, os.listdir(path))

    for file in files:
        if CRITERIA_SIG_FILE in file:
            return join(path, file)
    
    return None

def hash_file_parse(path: str, clause: str) -> List[Dict[str, str]]:
    data: List[str] = []
    file: Final[str] = find_signature_file(path)
    line: str = None
    ret: List[Dict[str, str]] = []

    if file is None or clause is None:
        return []
    
    with open(file, "r") as f:
        for lines in f:
            if "#" in lines:
                continue

            line = lines.rstrip("\n")
            data = line.split(" ", 2)

            if clause == '*':
                ret.append({'file': data[0], 'hash': data[1]})
                continue
            
            if clause in data[0]:
                ret.append({'file': data[0], 'hash': data[1]})
            
    return ret

def hash_verify(path: str, sig_path: str, clause: str) -> bool:
    computed_hash: Final[List[Dict[str, str]]] = hash_file_parse(sig_path, clause)
    computed_hash_length: Final[int] = len(computed_hash)
    hashes: List[Dict[str, str]] = []
    amount: int = 0
    ret: bool = False
    verifications: int = 0

    if computed_hash_length == 0:
        return False

    for file in filter(os.path.isfile, os.listdir(path)):
        if clause == '*':
            with open(file, "rb", buffering=0) as f:
                hashes.append({'file': file, 'hash': file_digest(f, HASH_ALGORITHM).hexdigest()})
        elif clause in file:
            with open(file, "rb", buffering=0) as f:
                hashes.append({'file': file, 'hash': file_digest(f, HASH_ALGORITHM).hexdigest()})

    amount = len(hashes)

    for current in hashes:
        for old in computed_hash:
            for curr_file, curr_hash in current.items():
                for old_file, old_hash in old.items():
                    if curr_file in old_file:
                        if (set(curr_hash).issubset(hexdigits)):
                            LOG.info(f"[{verifications}/{amount}] Verifying hash with known hash signature")
                            ret = curr_hash == old_hash
                            verifications += 1
    
    return ret and verifications == computed_hash_length

def process_active(process: str) -> bool:
    '''
    Determine if a process is active using TASKLIST.

    See: https://stackoverflow.com/questions/7787120/check-if-a-process-is-running-or-not-on-windows/29275361#29275361
    '''
    process = process.lower()
    # use buildin check_output right away
    output: str = check_output(['TASKLIST', '/FI', f'imagename eq {process}']).decode('utf-8').lower()
    # check in last line for process name
    last_line: str = output.strip().split('\r\n')[-1]
    # because Fail message could be translated
    return last_line.startswith(process)

def process_terminate(exe: str) -> bool:
    if not process_active(exe):
        return True
    
    try:
        ret_code: int = os.system(f"taskkill /f /im  {exe}")
        return ret_code == 128 or ret_code == 0
    except Exception as e:
        LOG.exception("Failed to execute taskkill")
        return False

def main() -> int:
    formatter: logging.Formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
    log_file: logging.FileHandler = logging.FileHandler('mpv-updater.log')
    archives: Final[List[str]] = fetch_archives()
    archive_count = 0
    archives_size: Final[int] = len(archives)
    current: int = 1
    tmp: tempfile.TemporaryDirectory = tempfile.TemporaryDirectory(prefix='open-in-mpv')

    log_file.setLevel(logging.DEBUG)
    log_file.setFormatter(formatter)
    LOG.addHandler(log_file)
    LOG.setLevel(logging.DEBUG)

    if archives == 0:
        LOG.error("Failed to fetch the needed archives.")
        tmp.cleanup()
        return 0
    
    # Verify all archives are downloaded.
    for archive in archives:
        files: filter = filter(os.path.isfile, os.listdir(tmp.name))
        for file in files:
            if file in FILES_SEARCH:
                archive_count += 1

    if archive_count != 4:
        LOG.error("Failed to fetch all archives for updating.")
        return 0

    # Download archives to the new temp directory.
    for archive in archives:
        LOG.info(f"[{current}/{archives_size}] Downloading {archive.split('/')[-1]}...")
        download_file(tmp.name, archive)
        current += 1
    
    # TODO fix the signature file path.

    # Verify the archives.
    if not hash_verify(tmp.name, None, '.tar.gz'):
        LOG.error("Failed to verify the archives.")
        return 0
    
    # Extract the archives.
    for file in find_files('.tar.gz', tmp.name):
        if not decompress(TAR, [tmp.name, file]):
            LOG.error(f"Failed to extract {file} at {tmp.name}")
            continue

    # Hash verify the contents.
    if not hash_verify(tmp.name, None, '*'):
        LOG.error("Failed to verify executable.")
        return 0
    
    # Replace out of date executables.
    for file in FILES:
        if not process_terminate(file):
            LOG.error(f"Failed to terminate process. {file}")
            return 0
        
        shutil.move(join(tmp.name, file), join(join(os.environ["ProgramFiles"], "open-in-mpv"), file))
    
    LOG.info("Updating completed")
    return 1

if __name__ == '__main__':
    sys.exit(main())
