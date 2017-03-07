#!/usr/bin/env python
# encoding: utf-8
'''
Collector -- Crash processing client

Provide process and class level interfaces to process crash information with
a remote server.

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
'''

# Ensure print() compatibility with Python 3
from __future__ import print_function

import argparse
import base64
import hashlib
import json
import os
import platform
import requests
import sys
from tempfile import mkstemp
import time
from zipfile import ZipFile

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FTB_PATH = os.path.abspath(os.path.join(BASE_DIR, ".."))
sys.path += [BASE_DIR]

from ConfigurationFiles import ConfigurationFiles
from ProgramConfiguration import ProgramConfiguration
from Signatures.CrashInfo import CrashInfo

__all__ = []
__version__ = 0.1
__date__ = '2014-10-01'
__updated__ = '2014-10-01'

def remote_checks(f):
    'Decorator to perform error checks before using remote features'
    def decorator(self, *args, **kwargs):
        if not self.serverHost:
            raise RuntimeError("Must specify serverHost (configuration property: serverhost) to use remote features.")
        if not self.serverHost:
            raise RuntimeError("Must specify serverAuthToken (configuration property: serverauthtoken) to use remote features.")
        if not self.tool:
            raise RuntimeError("Must specify tool (configuration property: tool) to use remote features.")
        return f(self, *args, **kwargs)
    return decorator

def signature_checks(f):
    'Decorator to perform error checks before using signature features'
    def decorator(self, *args, **kwargs):
        if not self.sigCacheDir:
            raise RuntimeError("Must specify sigCacheDir (configuration property: sigdir) to use signatures.")
        return f(self, *args, **kwargs)
    return decorator

class Collector():
    def __init__(self, sigCacheDir=None, serverHost=None, serverPort=None,
                 serverProtocol=None, serverAuthToken=None,
                 clientId=None, tool=None):
        '''
        Initialize the Collector. This constructor will also attempt to read
        a configuration file to populate any missing properties that have not
        been passed to this constructor.

        @type sigCacheDir: string
        @param sigCacheDir: Directory to be used for caching signatures
        @type serverHost: string
        @param serverHost: Server host to contact for refreshing signatures
        @type serverPort: int
        @param serverPort: Server port to use when contacting server
        @type serverAuthToken: string
        @param serverAuthToken: Token for server authentication
        @type clientId: string
        @param clientId: Client ID stored in the server when submitting issues
        @type tool: string
        @param tool: Name of the tool that found this issue
        '''
        self.sigCacheDir = sigCacheDir
        self.serverHost = serverHost
        self.serverPort = serverPort
        self.serverProtocol = serverProtocol
        self.serverAuthToken = serverAuthToken
        self.clientId = clientId
        self.tool = tool

        # Now search for the global configuration file. If it exists, read its contents
        # and set all Collector settings that haven't been explicitely set by the user.
        globalConfigFile = os.path.join(os.path.expanduser("~"), ".fuzzmanagerconf")
        if os.path.exists(globalConfigFile):
            configInstance = ConfigurationFiles([ globalConfigFile ])
            globalConfig = configInstance.mainConfig

            if self.sigCacheDir is None and "sigdir" in globalConfig:
                self.sigCacheDir = globalConfig["sigdir"]

            if self.serverHost is None and "serverhost" in globalConfig:
                self.serverHost = globalConfig["serverhost"]

            if self.serverPort is None and "serverport" in globalConfig:
                self.serverPort = int(globalConfig["serverport"])

            if self.serverProtocol is None and "serverproto" in globalConfig:
                self.serverProtocol = globalConfig["serverproto"]

            if self.serverAuthToken is None:
                if "serverauthtoken" in globalConfig:
                    self.serverAuthToken = globalConfig["serverauthtoken"]
                elif "serverauthtokenfile" in globalConfig:
                    with open(globalConfig["serverauthtokenfile"]) as f:
                        self.serverAuthToken = f.read().rstrip()

            if self.clientId is None and "clientid" in globalConfig:
                self.clientId = globalConfig["clientid"]

            if self.tool is None and "tool" in globalConfig:
                self.tool = globalConfig["tool"]

        # Set some defaults that we can't set through default arguments, otherwise
        # they would overwrite configuration file settings
        if self.serverProtocol is None:
            self.serverProtocol = "https"

        # Try to be somewhat intelligent about the default port, depending on protocol
        if self.serverPort is None:
            if self.serverProtocol == "https":
                self.serverPort = 433
            else:
                self.serverPort = 80

        if self.serverHost is not None and self.clientId is None:
            self.clientId = platform.node()

    @remote_checks
    @signature_checks
    def refresh(self):
        '''
        Refresh signatures by contacting the server, downloading new signatures
        and invalidating old ones.
        '''
        url = "%s://%s:%d/crashmanager/files/signatures.zip" % (self.serverProtocol, self.serverHost, self.serverPort)

        # We need to use basic authentication here because these files are directly served by the HTTP server
        response = requests.get(url, stream=True, auth=('fuzzmanager', self.serverAuthToken))

        if response.status_code != requests.codes["ok"]:
            raise self.__serverError(response)

        (zipFileFd, zipFileName) = mkstemp(prefix="fuzzmanager-signatures")

        with os.fdopen(zipFileFd, 'w') as zipFile:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    zipFile.write(chunk)
                    zipFile.flush()

        self.refreshFromZip(zipFileName)
        os.remove(zipFileName)



    @remote_checks
    def submit(self, crashInfo, testCase=None, testCaseQuality=0, metaData=None):
        '''
        Submit the given crash information and an optional testcase/metadata
        to the server for processing and storage.

        @type crashInfo: CrashInfo
        @param crashInfo: CrashInfo instance obtained from L{CrashInfo.fromRawCrashData}

        @type testCase: string
        @param testCase: A file containing a testcase for reproduction

        @type testCaseQuality: int
        @param testCaseQuality: A value indicating the quality of the test (less is better)

        @type metaData: map
        @param metaData: A map containing arbitrary (application-specific) data which
                         will be stored on the server in JSON format. This metadata is combined
                         with possible metadata stored in the L{ProgramConfiguration} inside crashInfo.
        '''
        url = "%s://%s:%d/crashmanager/rest/crashes/" % (self.serverProtocol, self.serverHost, self.serverPort)

        # Serialize our crash information, testcase and metadata into a dictionary to POST
        data = {}

        data["rawStdout"] = os.linesep.join(crashInfo.rawStdout)
        data["rawStderr"] = os.linesep.join(crashInfo.rawStderr)
        data["rawCrashData"] = os.linesep.join(crashInfo.rawCrashData)

        if testCase:
            (testCaseData, isBinary) = Collector.read_testcase(testCase)

            if isBinary:
                testCaseData = base64.b64encode(testCaseData)

            data["testcase"] = testCaseData
            data["testcase_isbinary"] = isBinary
            data["testcase_quality"] = testCaseQuality
            data["testcase_ext"] = os.path.splitext(testCase)[1].lstrip(".")

        data["platform"] = crashInfo.configuration.platform
        data["product"] = crashInfo.configuration.product
        data["os"] = crashInfo.configuration.os

        if crashInfo.configuration.version:
            data["product_version"] = crashInfo.configuration.version

        data["client"] = self.clientId
        data["tool"] = self.tool

        if crashInfo.configuration.metadata or metaData:
            aggrMetaData = {}

            if crashInfo.configuration.metadata:
                aggrMetaData.update(crashInfo.configuration.metadata)

            if metaData:
                aggrMetaData.update(metaData)

            data["metadata"] = json.dumps(aggrMetaData)

        if crashInfo.configuration.env:
            data["env"] = json.dumps(crashInfo.configuration.env)

        if crashInfo.configuration.args:
            data["args"] = json.dumps(crashInfo.configuration.args)

        current_timeout = 2
        while True:
            response = requests.post(url, data, headers=dict(Authorization="Token %s" % self.serverAuthToken))

            if response.status_code != requests.codes["created"]:
                # Allow for a total sleep time of up to 2 minutes if it's
                # likely that the response codes indicate a temporary error
                retry_codes = [500, 502, 503, 504]
                if response.status_code in retry_codes and current_timeout <= 64:
                    time.sleep(current_timeout)
                    current_timeout *= 2
                    continue

                raise self.__serverError(response)
            else:
                break


    @staticmethod
    def __serverError(response):
        return RuntimeError("Server unexpectedly responded with status code %s: %s" %
                            (response.status_code, response.text))

    @staticmethod
    def read_testcase(testCase):
        '''
        Read a testcase file, return the content and indicate if it is binary or not.

        @type testCase: string
        @param testCase: Filename of the file to open

        @rtype: tuple(string, bool)
        @return: Tuple containing the file contents and a boolean indicating if the content is binary

        '''
        with open(testCase) as f:
            testCaseData = f.read()

            textBytes = bytearray([7, 8, 9, 10, 12, 13, 27]) + bytearray(range(0x20, 0x100))
            isBinary = lambda input: bool(input.translate(None, textBytes))

            return (testCaseData, isBinary(testCaseData))

def main():
    stdout = None
    stderr = None
    crashdata = None
    crashInfo = None
    args = None
    env = None
    metadata = {}
    product = 'test_product'
    platform = 'x86'
    os = 'linux'
    product_version = '1.0'
    testcase = '/tmp/a.js'
    stdout = 'test_stdout'
    stderr = 'test_stderr'
    crashdata = 'test_crashdata'
    testcasequality = 0
    tool = 'test_tool'
    # metadata = 'test_metadata'

    configuration = ProgramConfiguration(product, platform,
                                            os, product_version,
                                            env, args, metadata)


    crashInfo = CrashInfo.fromRawCrashData(stdout, stderr, configuration, auxCrashData=crashdata)
    if testcase:
        (testCaseData, isBinary) = Collector.read_testcase(testcase)
        if not isBinary:
            crashInfo.testcase = testCaseData

    collector = Collector(sigCacheDir='/tmp/sigcache', tool=tool)

    
    collector.submit(crashInfo, testcase, testcasequality)
    return 0


if __name__ == "__main__":
    sys.exit(main())
