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
import re

from utils import *
from report import *
from log_parser import StatusCode, BatchResultParser

def getMustpassDir(api, releaseTagStr):

	mustpassDir = 'master'
	matchFound = False
	for r in NOT_MASTER_DIR:
		if re.match(r, releaseTagStr):
			matchFound = True
			break

	if matchFound:
		prefix			= RELEASE_TAG_DICT[api] + '-'
		releaseVer		= releaseTagStr[len(prefix):]
		idx				= releaseVer.rfind('.')
		mustpassDir		= releaseVer[:idx]

	return mustpassDir

def getMustpassName(api):
	assert api == 'VK' or api == 'VKSC'

	if api == "VK":
		return "vk-default.txt"
	elif api == "VKSC":
		return "vksc-default.txt"

	return None

def getMustpass (report, api, ctsPath, releaseTagStr):
	report.message("Fetching mustpass for %s." % releaseTagStr)
	pushWorkingDir(ctsPath)

	mustpassDir	= getMustpassDir(api, releaseTagStr)
	mustpassName	= getMustpassName(api)
	mustpassPath	= os.path.join(ctsPath, 'external', 'vulkancts', 'mustpass', mustpassDir, mustpassName)
	mustpass	= Mustpass(mustpassPath)

	fractionMustpassPath	= os.path.join(ctsPath, 'external', 'vulkancts', 'mustpass', mustpassDir, 'vk-fraction-mandatory-tests.txt')
	fractionMustpass = None
	if os.path.isfile(fractionMustpassPath):
		fractionMustpass = Mustpass(fractionMustpassPath)

	popWorkingDir()
	result = True

	if mustpass.read(report) and (fractionMustpass is None or fractionMustpass.read(report)):
		report.message("Successfully fetched mustpass for %s, num tests %d" % (releaseTagStr, len(mustpass.cases)))
	else:
		report.failure("Failed to fetch mustpass for %s" % releaseTagStr)
		result = False

	return result, mustpass, fractionMustpass

def verifyTestLogs (report, package, mustpass, fractionMustpass, gitSHA):

	report.message("Verifying test logs")
	anyError = False
	anyError |= verifyTestLog(report, package, mustpass, fractionMustpass, gitSHA)

	if len(package.testLogs) == 0:
		report.failure("No test log files found")
		anyError |= True

	if anyError:
		report.failure("Verification of test logs FAILED")
	else:
		report.passed("Verification of test logs PASSED")

def verify_vk (report, verfification, package, gitSHA):
	releaseTagStr = verfification.releaseTag
	success, mustpass, fractionMustpass = getMustpass(report, verfification.api, verfification.ctsPath, releaseTagStr)
	if success:
		verifyTestLogs(report, package, mustpass, fractionMustpass, gitSHA)
