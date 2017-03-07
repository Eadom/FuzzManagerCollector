'''
Matchers

Various matcher classes required by crash signatures

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
'''

# Ensure print() compatibility with Python 3
from __future__ import print_function

import re
from Signatures import JSONHelper

class StringMatch():
    def __init__(self, obj):
        self.isPCRE = False
        self.compiledValue = None

        if isinstance(obj, str) or isinstance(obj, unicode):
            self.value = str(obj)

            # Support the short form using forward slashes to indicate a PCRE
            if self.value.startswith("/") and self.value.endswith("/"):
                self.isPCRE = True
                self.value = self.value[1:-1]
                try:
                    self.compiledValue = re.compile(self.value)
                except re.error as e:
                    raise RuntimeError("Error in regular expression: %s" % e)
        else:
            self.value = JSONHelper.getStringChecked(obj, "value", True)

            matchType = JSONHelper.getStringChecked(obj, "matchType", False)
            if matchType != None:
                if matchType.lower() == "contains":
                    pass
                elif matchType.lower() == "pcre":
                    self.isPCRE = True
                    try:
                        self.compiledValue = re.compile(self.value)
                    except re.error as e:
                        raise RuntimeError("Error in regular expression: %s" % e)
                else:
                    raise RuntimeError("Unknown match operator specified: %s" % matchType)

    def matches(self, val):
        if self.isPCRE:
            return self.compiledValue.search(val) != None
        else:
            return self.value in val

    def __str__(self):
        return self.value

    def __repr__(self):
        if (self.isPCRE):
            return '/%s/' % self.value

        return self.value

class NumberMatchType:
    GE, GT, LE, LT = range(4)

class NumberMatch():
    def __init__(self, obj):
        self.matchType = None

        if isinstance(obj, str) or isinstance(obj, unicode):
            if len(obj) > 0:
                numberMatchComponents = obj.split(None, 1)
                numIdx = 0

                if len(numberMatchComponents) > 1:
                    numIdx = 1
                    matchType = numberMatchComponents[0]

                    if matchType == "==":
                        pass
                    elif matchType == "<":
                        self.matchType = NumberMatchType.LT
                    elif matchType == "<=":
                        self.matchType = NumberMatchType.LE
                    elif matchType == ">":
                        self.matchType = NumberMatchType.GT
                    elif matchType == ">=":
                        self.matchType = NumberMatchType.GE
                    else:
                        raise RuntimeError("Unknown match operator specified: %s" % matchType)

                try:
                    self.value = long(numberMatchComponents[numIdx], 16)
                except ValueError:
                    raise RuntimeError("Invalid number specified: %s" % numberMatchComponents[numIdx])
            else:
                # We're trying to match the fact that we cannot calculate a crash address
                self.value = None

        elif isinstance(obj, int):
            self.value = obj
        else:
            raise RuntimeError("Invalid type %s in NumberMatch." % type(obj))

    def matches(self, value):
        if value == None:
            return self.value == None

        if self.matchType == NumberMatchType.GE:
            return value >= self.value
        elif self.matchType == NumberMatchType.GT:
            return value > self.value
        elif self.matchType == NumberMatchType.LE:
            return value <= self.value
        elif self.matchType == NumberMatchType.LT:
            return value < self.value
        else:
            return value == self.value
