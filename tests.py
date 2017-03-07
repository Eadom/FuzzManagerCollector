'''
Tests

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
'''
import re
import unittest
from FTB import AssertionHelper

asanFFAbort = """Hit MOZ_CRASH() at /srv/repos/browser/mozilla-central/memory/mozalloc/mozalloc_abort.cpp:30
ASAN:SIGSEGV
=================================================================
==26289==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7fac9b54873a sp 0x7fff085f2120 bp 0x7fff085f2130 T0)
"""

asanOverflow = """
==26403==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60300021e6c8 at pc 0x7f30b3d276ef bp 0x7f30a521c8c0 sp 0x7f30a521c8b8
READ of size 8 at 0x60300021e6c8 thread T20 (MediaPlayback #1)
"""

jsshellMozCrash = """
Hit MOZ_CRASH(named lambda static scopes should have been skipped) at /srv/repos/mozilla-central/js/src/vm/ScopeObject.cpp:1277
"""

v8Abort = """
#
# Fatal error in ../src/compiler.cc, line 219
# Check failed: !feedback_vector_->metadata()->SpecDiffersFrom( literal()->feedback_vector_spec()).
#
"""

windowsPathAssertFwdSlashes = """
Assertion failure: block->graph().osrBlock(), at c:/Users/fuzz1win/trees/mozilla-central/js/src/jit/Lowering.cpp:4691
"""

windowsPathAssertBwSlashes = r"""
Assertion failure: block->graph().osrBlock(), at c:\Users\fuzz1win\trees\mozilla-central\js\src\jit\Lowering.cpp:4691
"""

class AssertionHelperTestASanFFAbort(unittest.TestCase):
    def runTest(self):
        err = asanFFAbort.splitlines()

        self.assertEqual(AssertionHelper.getAssertion(err), None)
        self.assertEqual(AssertionHelper.getAuxiliaryAbortMessage(err), None)

class AssertionHelperTestMozCrash(unittest.TestCase):
    def runTest(self):
        err = jsshellMozCrash.splitlines()

        sanitizedMsg = AssertionHelper.getSanitizedAssertionPattern(AssertionHelper.getAssertion(err))
        expectedMsg = "Hit MOZ_CRASH\\(named lambda static scopes should have been skipped\\) at ([a-zA-Z]:)?/.+/ScopeObject\\.cpp:[0-9]+"

        self.assertEqual(sanitizedMsg, expectedMsg)

class AssertionHelperTestV8Abort(unittest.TestCase):
    def runTest(self):
        err = v8Abort.splitlines()

        sanitizedMsgs = AssertionHelper.getSanitizedAssertionPattern(AssertionHelper.getAssertion(err))
        self.assertTrue(isinstance(sanitizedMsgs, list))
        self.assertEqual(len(sanitizedMsgs), 2)

        expectedMsgs = [
                         "# Fatal error in \\.\\./src/compiler\\.cc, line [0-9]+",
                         "# Check failed: !feedback_vector_\\->metadata\\(\\)\\->SpecDiffersFrom\\( literal\\(\\)\\->feedback_vector_spec\\(\\)\\)\\."
        ]

        self.assertEqual(sanitizedMsgs[0], expectedMsgs[0])
        self.assertEqual(sanitizedMsgs[1], expectedMsgs[1])

class AssertionHelperTestWindowsPathSanitizing(unittest.TestCase):
    def runTest(self):
        err1 = windowsPathAssertFwdSlashes.splitlines()
        err2 = windowsPathAssertBwSlashes.splitlines()

        assertionMsg1 = AssertionHelper.getAssertion(err1)
        assertionMsg2 = AssertionHelper.getAssertion(err2)

        sanitizedMsg1 = AssertionHelper.getSanitizedAssertionPattern(assertionMsg1)
        sanitizedMsg2 = AssertionHelper.getSanitizedAssertionPattern(assertionMsg2)

        expectedMsg = "Assertion failure: block\\->graph\\(\\)\\.osrBlock\\(\\), at ([a-zA-Z]:)?/.+/Lowering\\.cpp:[0-9]+"

        self.assertEqual(sanitizedMsg1, expectedMsg)

        # We currently don't support backward slashes, but if we add support, uncomment this test
        # self.assertEqual(sanitizedMsg2, expectedMsg)

        self.assertTrue(re.match(expectedMsg, assertionMsg1))

        # We currently don't support backward slashes, but if we add support, uncomment this test
        # self.assertTrue(re.match(expectedMsg, assertionMsg2))

class AssertionHelperTestAuxiliaryAbortASan(unittest.TestCase):
    def runTest(self):
        err = asanOverflow.splitlines()

        sanitizedMsg = AssertionHelper.getSanitizedAssertionPattern(AssertionHelper.getAuxiliaryAbortMessage(err))
        expectedMsg = [
             "ERROR: AddressSanitizer: heap\\-buffer\\-overflow",
             "READ of size 8 at 0x[0-9a-fA-F]+ thread T[0-9]{2,} \\(MediaPlayback #1\\)"
             ]

        self.assertEqual(sanitizedMsg, expectedMsg)

if __name__ == "__main__":
    unittest.main()
