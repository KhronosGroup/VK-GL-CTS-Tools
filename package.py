# -*- coding: utf-8 -*-

#-------------------------------------------------------------------------
# VK-GL-CTS Conformance Submission Verification
# ---------------------------------------------
#
# Copyright 2020-2021 The Khronos Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#-------------------------------------------------------------------------

import os
from fnmatch import fnmatch
import re
from report import *
from utils import *

STATEMENT_PATTERN	= "STATEMENT-*"
TEST_LOG_PATTERN	= "*.qpa"
GIT_STATUS_PATTERN	= "*git-status.txt"
GIT_LOG_PATTERN		= "*git-log.txt"
PATCH_PATTERN		= "*.patch"
SUMMARY_PATTERN		= "cts-run-summary.xml"
FRACTION_REGEX		= ".*[0-9]-of-[0-9].qpa"

class PackageDescription:
	def __init__ (self, basePath, statement,
				  testLogs, gitStatus, gitLog,
				  patches, summary, conformVersion,
				  conformOs, product, cpu, otherItems):
		self.basePath		= basePath
		self.statement		= statement
		self.testLogs		= testLogs
		self.gitStatus		= gitStatus
		self.gitLog			= gitLog
		self.patches		= patches
		self.summary		= summary
		self.otherItems		= otherItems
		self.conformVersion	= conformVersion
		self.conformOs		= conformOs
		self.conformProduct	= product
		self.conformCpu		= cpu

def getPackageDescription (report, packagePath):
	allItems		= os.listdir(packagePath)
	statement		= None
	testLogs		= []
	gitStatus		= []
	gitLog			= []
	patches			= []
	summary			= None
	otherItems		= []
	conformVersion	= None
	conformOs		= None
	conformProduct	= []
	conformCpu		= None
	testLogsFraction= {}

	reobj = re.compile(FRACTION_REGEX)
	isFraction = False
	for item in allItems:
		if fnmatch(item, STATEMENT_PATTERN):
			assert statement == None
			statement = item
		elif fnmatch(item, TEST_LOG_PATTERN):
			testLogs.append(item)
			isFraction = isFraction or (reobj.match(item) != None)
		elif fnmatch(item, GIT_STATUS_PATTERN):
			gitStatus.append(item)
		elif fnmatch(item, GIT_LOG_PATTERN):
			gitLog.append((item, '.'))
		elif fnmatch(item, PATCH_PATTERN):
			patches.append(item)
		elif fnmatch(item, SUMMARY_PATTERN):
			assert summary == None
			summary = item
		else:
			otherItems.append(item)

	if isFraction:
		for log in testLogs:
			if reobj.match(log) == None:
				report.failure("The package contains at least one test log file generated using --deqp-fraction option. All test log files in the package must be generated using that option. Test log file %s doesn't follow this requirement." % (log))
	for log in testLogs:
		prefix = re.split("(\d-of-\d)+", log)[0]
		if prefix in testLogsFraction:
			fractionLogs = testLogsFraction[prefix]
		else:
			fractionLogs = []
			testLogsFraction[prefix] = fractionLogs

		fractionLogs.append(log)

	for key, filesList in testLogsFraction.items():
		filesList.sort()

	return PackageDescription(packagePath, statement, testLogsFraction,
							  gitStatus, gitLog, patches,
							  summary, conformVersion, conformOs,
							  conformProduct, conformCpu, otherItems)

def findStatement(report, packagePath):
	report.message("Looking for STATEMENT")
	allItems = os.listdir(packagePath)

	statement = None
	for item in allItems:
		if fnmatch(item, STATEMENT_PATTERN):
			if statement != None:
				report.failure("Found more than one STATEMENT")
				report.generate(RETURN_CODE_FAIL)
			else:
				statement = item

	if statement == None:
		report.failure("Found no STATEMENT")
		report.generate(RETURN_CODE_FAIL)
	else:
		report.passed("STATEMENT found", statement)
	return statement

def findReleaseTag(report, packagePath):
	statementFile	= findStatement(report, packagePath)
	if statementFile == None:
		return None
	statementPath	= os.path.join(packagePath, statementFile)
	statement		= readFile(statementPath)

	hasVersion = False
	conformVersion = None
	report.message("Looking for CONFORM_VERSION")
	for line in statement.splitlines():
		if beginsWith(line, b"CONFORM_VERSION:"):
			if hasVersion:
				report.failure("Multiple CONFORM_VERSIONs", statementFile)
				report.generate(RETURN_CODE_FAIL)
			else:
				assert len(line.split()) >= 2
				conformVersion = line.split()[1]
				hasVersion = True

	if conformVersion != None:
		report.passed("CONFORM_VERSION found %s" % conformVersion, statementFile)
	else:
		report.failure("CONFORM_VERSION not found", statementFile)
		report.generate(RETURN_CODE_FAIL)
	return conformVersion
