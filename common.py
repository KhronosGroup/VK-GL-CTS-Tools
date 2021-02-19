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
import re

from package import *
from utils import *
from verify_vk import *
from verify_es import *

def isKCCTSRelease(releaseTagStr):
	for r in KC_CTS_RELEASE:
		if re.match(r, releaseTagStr):
			return True
	return False

def verifyReleaseTagAndApi(report, ctsPath, api, releaseTag):
	releaseTagStr = releaseTag
	if not beginsWith(releaseTagStr, RELEASE_TAG_DICT[api]):
		report.failure("Release tag %s is not supported by automated verification" % releaseTagStr)
		return False

	matchFound = False
	for r in WITHDRAWN_RELEASES:
		if re.match(r, releaseTagStr):
			matchFound = True
			break

	if matchFound == True:
		report.failure("Release tag %s was withdrawn. Submissions against this tag are invalid." % releaseTagStr)
		return False

	matchFound = False
	for r in SUPPORTED_RELEASES:
		if re.match(r, releaseTagStr):
			matchFound = True
			break

	if matchFound == False:
		report.failure("Release tag %s is not supported by automated verification" % releaseTagStr)
		return False

	pushWorkingDir(ctsPath)
	try:
		result = git('tag', '-l', releaseTagStr)
	except:
		pass
	else:
		if result.strip('\r\n') != releaseTagStr:
			report.failure("Failed to find tag %s in VK-GL-CTS" % releaseTagStr)
			return False
	popWorkingDir()

	report.message("Verifying against %s" % releaseTagStr)
	return True

def getReleaseLog (report, ctsPath, releaseTagStr):
	releaseLog 		= [None, None]
	report.message("Fetching HEAD commit of %s." % releaseTagStr)
	pushWorkingDir(ctsPath)
	checkoutReleaseTag(report, releaseTagStr)
	releaseLog[0] = git('log', '-1', '--decorate=no', releaseTagStr)
	if isKCCTSRelease(releaseTagStr):
		kcctsDir = os.path.join(ctsPath, 'external', 'kc-cts', 'src')
		pushWorkingDir(kcctsDir)
		releaseLog[1] = git('log', '-1', '--decorate=no', releaseTagStr)
		popWorkingDir()
	popWorkingDir()

	report.message("Successfully fetched HEAD commit of %s" % releaseTagStr)
	return releaseLog

def getGitCommitFromLog(package):
	for logFile, path in package.gitLog:
		if "kc-cts" in logFile:
			continue
		logPath	= os.path.join(package.basePath, logFile)
		log		= readFile(logPath)
		for line in log.splitlines():
			args = line.decode('utf-8', 'ignore').split(' ')
			if args[0] == "commit":
				return args[1]
	return "invalid"

def verifyStatement (report, package):

	assert package.statement != None

	report.message("Verifying STATEMENT", package.statement)
	statementPath	= os.path.join(package.basePath, package.statement)
	statement		= readFile(statementPath)
	hasVersion		= False
	hasProduct		= False
	hasCpu			= False
	hasOs			= False
	anyError		= False

	for line in statement.splitlines():
		line = line.decode('utf-8', 'ignore')
		if beginsWith(line, "CONFORM_VERSION:"):
			if hasVersion:
				report.failure("Multiple CONFORM_VERSIONs", package.statement)
				anyError = True
			else:
				package.conformVersion = (line[line.find(':') + 1:]).lstrip(' \t')
				hasVersion = True
		elif beginsWith(line, "PRODUCT:"):
			hasProduct = True # Multiple products allowed
			package.conformProduct.append((line[line.find(':') + 1:]).lstrip(' \t'))
		elif beginsWith(line, "CPU:"):
			if hasCpu:
				report.failure("Multiple CPUs", package.statement)
				anyError = True
			else:
				hasCpu = True
				package.conformCpu = (line[line.find(':') + 1:]).lstrip(' \t')
		elif beginsWith(line, "OS:"):
			if hasOs:
				report.failure("Multiple OSes", package.statement)
				anyError = True
			else:
				package.conformOs = (line[line.find(':') + 1:]).lstrip(' \t')
				hasOs = True

	if not hasVersion:
		report.failure("No CONFORM_VERSION", package.statement)
		anyError = True
	if not hasProduct:
		report.failure("No PRODUCT", package.statement)
		anyError = True
	if not hasCpu:
		report.failure("No CPU", package.statement)
		anyError = True
	if not hasOs:
		report.failure("No OS", package.statement)
		anyError = True

	if anyError:
		report.failure("Verification of STATEMENT FAILED", package.statement)
	else:
		report.passed("Verification of STATEMENT PASSED", package.statement)
		statementMsg = "CONFORM_VERSION:\t" + package.conformVersion
		for p in package.conformProduct:
			statementMsg += "\nPRODUCT:\t\t\t" + p
		statementMsg += "\nCPU:\t\t\t\t" + package.conformCpu
		statementMsg += "\nOS:\t\t\t\t\t" + package.conformOs
		statementMsg += "\n"
		report.fmtmessage(statementMsg)

def getNumStatusfiles(releaseTagStr):
	if isKCCTSRelease(releaseTagStr):
		return 2
	return 1

def verifyGitStatus (report, package):

	anyError = False
	if len(package.gitStatus) > 0:
		for s in package.gitStatus:
			statusPath	= os.path.join(package.basePath, s)
			status		= readFile(statusPath).decode('utf-8', 'ignore')

			if status.find("nothing to commit, working directory clean") < 0 and status.find("nothing to commit, working tree clean") < 0:
				report.failure("Working directory is not clean")
				anyError = True
	else:
		report.failure("Missing git status files")
		anyError = True

	return anyError

def verifyGitStatusFiles (report, package, releaseTagStr):
	anyError = False
	report.message("Verifying git status files.")
	msgDict = {1 : "one git status file", 2 : "two git status files"}
	numFiles = getNumStatusfiles(releaseTagStr)
	if len(package.gitStatus) != numFiles:
		report.failure("Exactly %s must be present, found %s" % (msgDict[numFiles], len(package.gitStatus)))
		anyError = True

	anyError |= verifyGitStatus(report, package)

	if anyError:
		report.failure("Verification of git status files FAILED")
	else:
		report.passed("Verification of git status files PASSED")

def sanitizePackageLog(log, report = None):
	slog = log.decode('utf-8', 'ignore')
	if report != None and slog != log:
		report.warning("git log contains non-decodable symbols")
	slog = slog.replace('\r\n', '\n')
	slog = slog.replace('\t', '        ')
	slog = re.sub(' \(.*(tag: .*)+\)', '', slog)
	return slog

def isGitLogEmpty (package, releaseLog, gitLog, report = None):
	logPath			= os.path.join(package.basePath, gitLog)
	prisitineLog	= readFile(logPath)
	log 			= sanitizePackageLog(prisitineLog, report)

	if report != None:
		report.message("git log contains:", gitLog)
		prisitineLog = prisitineLog.decode('utf-8', 'ignore')
		report.fmtmessage(prisitineLog)
	if log == releaseLog[0]:
		return True
	if releaseLog[1] != None and log == releaseLog[1]:
		return True
	return False

def isReleaseHeadInGitLog (report, package, releaseLog, gitLog):
	logPath	= os.path.join(package.basePath, gitLog)
	log		= readFile(logPath)
	log 	= sanitizePackageLog(log)

	if releaseLog[0] in log:
		return True
	if releaseLog[1] != None and releaseLog[1] in log:
		return True
	return False

def verifyGitLog (report, package, releaseLog):
	anyError = False
	anyWarn = False
	if len(package.gitLog) > 0:
		for log, path in package.gitLog:
			if isReleaseHeadInGitLog (report, package, releaseLog, log):
				report.passed("HEAD of %s is present in git log" % package.conformVersion)
			else:
				report.failure("HEAD of %s is NOT present in git log" % package.conformVersion)
				anyError |= True

			isEmpty = isGitLogEmpty(package, releaseLog, log, report)

			if isEmpty:
				report.passed("Log exactly matches HEAD of %s" % package.conformVersion)
			else:
				report.warning("Log is not empty", log)
				anyWarn |= True
	else:
		report.failure("Missing git log files")
		anyError = True

	return anyError, anyWarn

def verifyGitLogFiles (report, package, releaseLog, releaseTag):
	anyWarn = False
	anyError = False
	report.message("Verifying git log files")
	msgDict = {1 : "one git log file", 2 : "two git log files"}
	numFiles = getNumStatusfiles(releaseTag)

	if len(package.gitLog) != numFiles:
		report.failure("Exactly %s must be present, found %s" % (msgDict[numFiles], len(package.gitLog)))
		anyError = True

	logError , anyWarn = verifyGitLog(report, package, releaseLog)
	anyError |= logError

	if anyError:
		report.failure("Verification of git log files FAILED")
	if anyWarn:
		report.warning("Verification of git log files produced WARNINGS")
	if not anyError and not anyWarn:
		report.passed("Verification of git log files PASSED")

def verifyPatches (report, package, releaseLog):
	anyError = False
	report.message("Verifying patches")
	hasPatches	= len(package.patches)
	logEmpty	= True
	for log, path in package.gitLog:
		logEmpty &= isGitLogEmpty(package, releaseLog, log)

	if hasPatches and logEmpty:
		report.failure("Package includes patches but log is empty")
		anyError = True
	elif not hasPatches and not logEmpty:
		report.failure("Test log is not empty but package doesn't contain patches")
		anyError = True

	if anyError:
		report.failure("Verification of patch FAILED")
	else:
		report.passed("Verification of patches PASSED")

def verify (report, verfification):
	report.reportSubTitle("Package verification")
	res = verifyReleaseTagAndApi(report, verfification.ctsPath, verfification.api, verfification.releaseTag)
	if res == False:
		return
	releaseTagStr	= verfification.releaseTag
	package			= getPackageDescription(report, verfification.packagePath)
	releaseLog		= getReleaseLog(report, verfification.ctsPath, releaseTagStr)
	gitSHA			= getGitCommitFromLog(package)

	verifyStatement(report, package)
	verifyGitStatusFiles(report, package, releaseTagStr)
	verifyGitLogFiles(report, package, releaseLog, releaseTagStr)
	verifyPatches(report, package, releaseLog)

	if verfification.api == 'VK':
		verify_vk(report, verfification, package, gitSHA)
	elif verfification.api == 'GL' or verfification.api == 'ES':
		verify_es(report, verfification, package, gitSHA)

	for item in package.otherItems:
		report.failure("Unknown file", item)
