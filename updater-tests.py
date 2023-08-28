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

import platform
import os
import subprocess
import sys
import time
import unittest

from hashlib import file_digest
from io import StringIO as StringBuffer
from os.path import join
from typing import Dict, Final, List
from updater import (TAR, decompress, download_file, fetch_archives,
                    find_files, find_signature_file, hash_file_parse, 
                    hash_verify, process_active, process_terminate)

CALC: Final[str] = 'calc.exe'
CURRENT_DIRECTORY: Final[str] = f'.{os.sep}' # join removes the dot.
TEST_DIRECTORY: Final[str] = join(CURRENT_DIRECTORY, 'tests')

HASH_ALGORITHM: Final[str] = 'blake2b'
HASH_FILE_HEADER: Final[str] = f'# Generated by mpv-updater-tests\n# Copyright {time.strftime("%Y")} open-in-mpv Authors\n'
HASH_FORMAT: Final[str] = "{0} {1}\n"
TEST_DATA_ARCHIVES: Final[List[str]] = fetch_archives()
TEST_DATA_FILES: Final[List[str]] = ['README.md']
TEST_DATA_DECOMPRESS: Final[List[str]] = ['test_a.txt', 'test_b.txt']
TEST_DATA_DOWNLOAD_FILENAME: Final[str] = 'v1.0.1.zip'
TEST_DATA_DOWNLOAD_FILE_URL: Final[str] = 'https://github.com/movrsi/userjs/archive/refs/tags/v1.0.1.zip'
# Note: These hashes will need to be updated if any file changes. If you submit a pull request please update these, Thanks.
TEST_HASH_PARSE_DATA: Final[List[Dict[str, str]]] = [
    {'file': 'LICENSE', 'hash': '7997295a493f8bb6f3b913b56bf425a0fe6f77774c55884f04905b19362fdb150399c18c5698096dc97fa104107276069287abfc68b107231b55b5e99bef1cb9'},
    {'file': 'README.md', 'hash': 'd3779249e6861c8cf5f7699bb021f6a82bee81aa1eb4db15ab7cc20c201945272df868c61509080955fc3a5db130eac3e8aead70de41e08298d4bc8960b9fe01'},
    {'file': 'updater.py', 'hash': '954c54ea21c4c5c3bab19f9fe3aaaa6f1d13aa0afa72843f6404dae3c5990a0e6c7115180ceaa034fa598788af245a15c59f4d2e01e444c4631de1243af309cf'},
    {'file': 'updater-tests.py', 'hash': '5e8df9b7c3d15416056b333a1f27dbafc6f4434995c1fdb8245a8a51c47902940c1102d873b36caba49c3d24f197cf2cdc629c87c295585b83237c443c7fa86d'},
    {'file': '.gitignore', 'hash': 'e45ece8d79008ca1bc165ffd890002f98f79311d178e263c2ed0b496fd6aed80e283b0cac4e3e49bbc309da9386afef882caf6bbc96d911c96db17ed06db853c'}
]
TEST_PROCESS_ACTIVE: Final[str] = 'svchost.exe'
TEST_DATA_SIGNATURE_FILE: Final[str] = 'open-in-mpv-updates'

WINDOWS: Final[bool] = platform.win32_ver()[0]

def check_signature() -> bool:
    sig_check: filter = filter(None, os.listdir(TEST_DIRECTORY))

    for f in sig_check:
        if 'open-in-mpv-updates' in f:
            return True
    
    return False

def decompress_check() -> bool:
    files: filter = filter(None, os.listdir(CURRENT_DIRECTORY))
    occurrances: int = 0

    for file in files:
        if '.tar.gz' in file:
            continue

        if file in TEST_DATA_DECOMPRESS:
            occurrances += 1
    
    return occurrances == 2

def decompress_cleanup() -> None:
    try:
        os.remove(join(CURRENT_DIRECTORY, 'test_a.txt'))
        os.remove(join(CURRENT_DIRECTORY, 'test_b.txt'))
    except OSError:
        pass

def download_file_check() -> bool:
    files: filter = filter(None, os.listdir(TEST_DIRECTORY))

    for file in files:
        if file in TEST_DATA_DOWNLOAD_FILENAME:
            return True
        
    return False

def download_file_cleanup() -> None:
    try:
        os.remove(join(TEST_DIRECTORY, TEST_DATA_DOWNLOAD_FILENAME))
    except OSError:
        pass

def generate_hash_file() -> bool:
    if check_signature():
        return True
    
    files: filter = filter(os.path.isfile, os.listdir(CURRENT_DIRECTORY))
    buffer: StringBuffer = StringBuffer(initial_value=HASH_FILE_HEADER)
    filename: Final[str] = f'open-in-mpv-updates-{time.strftime("%Y%d%m")}.sig'
    
    for file in files:
        with open(join(CURRENT_DIRECTORY, file), 'rb') as f:
            buffer.write(HASH_FORMAT.format(file, file_digest(f, HASH_ALGORITHM).hexdigest()))

    with open(join(TEST_DIRECTORY, filename), 'w+') as sig:
        sig.write(buffer.getvalue())

    return os.path.isfile(join(TEST_DIRECTORY, filename))

class UpdaterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.maxDiff = None
    
    def test_decompression(self) -> None:
        if not decompress(TAR, join(TEST_DIRECTORY, 'test.tar.gz')):
            self.fail("Failed to decompress test archive.")
        
        self.assertTrue(decompress_check())
        decompress_cleanup()

    def test_download_file(self) -> None:
        file: Final[str] = download_file(TEST_DIRECTORY, TEST_DATA_DOWNLOAD_FILE_URL)
        
        if file is None:
            self.fail('Failed to download test archive.')

        self.assertEqual(TEST_DATA_DOWNLOAD_FILENAME, file)
        self.assertTrue(download_file_check())
        download_file_cleanup()

    def test_fetch_archives(self) -> None:
        archives: Final[List[str]] = fetch_archives()
        self.assertEqual(TEST_DATA_ARCHIVES, archives)

    def test_find_files_exists(self) -> None:
        self.assertEqual(TEST_DATA_FILES, find_files("md", CURRENT_DIRECTORY))
    
    def test_find_files_non_existant(self) -> None:
        self.assertEqual([], find_files("exe", CURRENT_DIRECTORY))

    def test_find_signature_file(self) -> None:
        self.assertTrue(TEST_DATA_SIGNATURE_FILE in find_signature_file(TEST_DIRECTORY))

    def test_hash_parse(self) -> None:
        self.assertEqual(TEST_HASH_PARSE_DATA, hash_file_parse(TEST_DIRECTORY, '*'))

    def test_harsh_verify(self) -> None:
        self.assertTrue(hash_verify(CURRENT_DIRECTORY, TEST_DIRECTORY, '.md'))


class WindowsTests(unittest.TestCase):
    '''
    Unit tests that can only be performed on Windows. a check is provided so the tests
    can run to a certain extent on Linux.
    '''
    def test_process_active(self) -> None:
        self.assertTrue(process_active(TEST_PROCESS_ACTIVE))

    def test_process_terminate(self) -> None:
        subprocess.run([CALC])
        # make sure calc is running before terminating.
        time.sleep(3.0)
        self.assertTrue(process_terminate(CALC))

if __name__ == '__main__':
    if not generate_hash_file():
        print('Failed to create test signature file')
        sys.exit(0)

    suites: Final[List[unittest.TestSuite]] = [
        unittest.TestLoader().loadTestsFromTestCase(UpdaterTests)
    ]
    
    if WINDOWS:
        suites.append(unittest.TestLoader().loadTestsFromTestCase(WindowsTests))

    suite: unittest.TestSuite = unittest.TestSuite(suites)
    textRunner: unittest.TextTestRunner = unittest.TextTestRunner(verbosity=2)
    textRunner.run(suite)
    