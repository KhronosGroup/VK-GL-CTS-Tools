# -*- coding: utf-8 -*-

#-------------------------------------------------------------------------
# VK-GL-CTS Conformance Submission Verification
# ---------------------------------------------
#
# Copyright 2020-2022 The Khronos Group Inc.
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
import pathlib
import subprocess
import sys
import tarfile
import tempfile

from report import *
from log_parser import StatusCode, BatchResultParser, CommandLineParser

ALLOWED_STATUS_CODES = set([
		StatusCode.PASS,
		StatusCode.WAIVED,
		StatusCode.NOT_SUPPORTED,
		StatusCode.QUALITY_WARNING,
		StatusCode.COMPATIBILITY_WARNING,
		StatusCode.WAIVER
	])

SUPPORTED_RELEASES	= ['vulkan-cts-[0-9]\.[0-9]\.[0-9]*\.[0-9]*',
					   'vulkansc-cts-1\.0\.[0-9]*\.[0-9]*',
					   'opengl-cts-4\.6\.[0-9]*\.[0-9]*',
					   'opengl-es-cts-3\.2\.([2-9]|[1-9][0-9]+)\.[0-9]*']
WITHDRAWN_RELEASES	= ['vulkan-cts-1\.0\.0\.[0-9]*',
				'vulkan-cts-1\.0\.1\.[0-9]*',
				'vulkan-cts-1\.0\.2\.[0-9]*',
				'vulkan-cts-1\.1\.0\.[0-9]*',
				'vulkan-cts-1\.1\.1\.[0-9]*',
				'vulkan-cts-1\.1\.2\.[0-9]*',
				'vulkan-cts-1\.1\.3\.[0-9]*',
				'vulkan-cts-1\.1\.4\.[0-9]*',
				'vulkan-cts-1\.1\.5\.[0-9]*',
				'vulkan-cts-1\.1\.6\.[0-9]*',
				'vulkan-cts-1\.2\.0\.[0-9]*',
				'vulkan-cts-1\.2\.1\.[0-9]*',
				'vulkan-cts-1\.2\.2\.[0-9]*',
				'vulkan-cts-1\.2\.3\.[0-9]*',
				'vulkan-cts-1\.2\.4\.[0-9]*',
				'vulkan-cts-1\.2\.5\.[0-9]*',
				'vulkan-cts-1\.2\.6\.[0-9]*',
				'vulkan-cts-1\.2\.7\.[0-9]*',
				'vulkan-cts-1\.2\.8\.[0-9]*',
				'vulkan-cts-1\.3\.0\.[0-9]*',
				'vulkan-cts-1\.3\.1\.[0-9]*',
				'vulkan-cts-1\.3\.2\.[0-9]*',
				'vulkan-cts-1\.3\.3\.[0-9]*',
				'vulkan-cts-1\.3\.4\.[0-9]*',
				'vulkan-cts-1\.3\.5\.[0-9]*',
				'vulkan-cts-1\.3\.6\.[0-9]*',
				'vulkansc-cts-1\.0\.0\.[0-9]*',
				'vulkansc-cts-1\.0\.1\.[0-9]*']
NOT_MASTER_DIR		= ['vulkan-cts-1\.0\.[0-9]*\.[0-9]*',
					   'vulkan-cts-1\.1\.0\.[0-9]*',
					   'vulkan-cts-1\.1\.1\.[0-9]*',
					   'vulkan-cts-1\.1\.2\.[0-9]*',
					   'vulkan-cts-1\.1\.3\.[0-9]*',
					   'vulkan-cts-1\.1\.4\.[0-9]*']
API_TYPE_DICT		= {'VK' : 'Vulkan', 'VKSC' : 'Vulkan SC', 'GL' : 'OpenGL', 'ES' : 'OpenGL ES'}
API_VERSION_REGEX	= ".*\-cts\-([0-9]+)\.([0-9]+)\..+"
RELEASE_TAG_DICT	= {'VK' : 'vulkan-cts', 'VKSC' : 'vulkansc-cts', 'ES' : 'opengl-es-cts', 'GL' : 'opengl-cts'}
KC_CTS_RELEASE		= ["opengl-es-cts-3\.2\.[2-3]\.[0-9]*", "opengl-cts-4\.6\.[0-9]*\.[0-9]*"]

class Mustpass:
	def __init__(self, filename):
		self.filename = filename
		self.basename = os.path.basename(filename)
		self.cases    = []

	def _read(self, report, filename):
		cases = []
		try:
			f = open(filename, 'rb')
		except Exception as e:
			report.failure("Failed to open %s" % (filename))
			return None

		dirname = os.path.dirname(filename)
		basename = os.path.basename(filename)

		for line in f:
			s = line.strip().decode('utf-8', 'ignore')
			if len(s) > 0:
				subfilename = os.path.join(dirname, s)
				if os.path.isfile(subfilename):
					subcases = self._read(report, subfilename)
					if subcases is not None:
						cases.extend(subcases)
					else:
						return None 
				else:
					cases.append(s)
		return cases

	def read(self, report):
		subcases = self._read(report, self.filename)
		if subcases is not None:
			self.cases = subcases
			return True
		else:
			return False

class CommandLineParserVk(CommandLineParser):

	def parse_args(self, args=None, namespace=None):
		args = super().parse_args(args, namespace)

		if args.deqp_vk_device_id < 1:
			raise Exception("--deqp-vk-device-id used invalid device id %d" % (args.deqp_vk_device_id))

		args.deqp_fraction = list(map(int, args.deqp_fraction.split(",")))

		if args.deqp_fraction[1] < 1 or args.deqp_fraction[1] > 16:
			raise Exception("--deqp-fraction count %d was specified out of range [1..16]" % (args.deqp_fraction[1]))

		if args.deqp_fraction[0] < 0 or args.deqp_fraction[0] >= args.deqp_fraction[1]:
			raise Exception("--deqp-fraction index %d was specified out of range [0..%d]" % (args.deqp_fraction[0], args.deqp_fraction[1] - 1))

		if args.deqp_fraction[1] > 1 and args.deqp_fraction_mandatory_caselist_file == None:
			raise Exception("fractional run specified without mandatory caselist file")

		return args

	def __init__(self, api):
		super(CommandLineParser, self).__init__(add_help=False, allow_abbrev=False)
		self.api = api

		#Common Args
		self.add_argument("--deqp-caselist-file",						type=pathlib.Path,				required=True)
		self.add_argument("--deqp-log-images",							choices=["disable"],			required=True)
		self.add_argument("--deqp-log-shader-sources",					choices=["disable"],			required=True)
		self.add_argument("--deqp-vk-device-id",						type=int,						default=1)
		self.add_argument("--deqp-log-flush",							choices=["enable", "disable"],	default="enable")
		self.add_argument("--deqp-log-filename",						type=pathlib.Path,				default=pathlib.Path("TestResults.qpa"))
		self.add_argument("--deqp-archive-dir",							type=pathlib.Path,				default=pathlib.Path("."))
		self.add_argument("--deqp-shadercache-filename",				type=pathlib.Path,				default=pathlib.Path("shadercache.bin"))
		self.add_argument("--deqp-shadercache",							choices=["enable", "disable"],	default="enable")
		self.add_argument("--deqp-fraction",															default="0,1")
		self.add_argument("--deqp-fraction-mandatory-caselist-file",	type=pathlib.Path,				default=None)
		self.add_argument("--deqp-waiver-file",							type=pathlib.Path,				default=None)
		self.add_argument("--deqp-log-decompiled-spirv",				choices=["enable", "disable"],	default="enable")
		self.add_argument("--deqp-log-empty-loginfo",					choices=["enable", "disable"],	default="enable")

		# VKSC args
		if self.api == "VKSC":
			self.add_argument("--deqp-command-buffer-min-size",	type=int,						default=0)
			self.add_argument("--deqp-command-pool-min-size",	type=int,						default=0)
			self.add_argument("--deqp-command-default-size",	type=int,						default=256)
			self.add_argument("--deqp-pipeline-default-size",	type=int,						default=16384)
			self.add_argument("--deqp-pipeline-compiler",		type=pathlib.Path,				default=None)
			self.add_argument("--deqp-pipeline-dir",			type=pathlib.Path,				default=None)
			self.add_argument("--deqp-pipeline-args",											default="")
			self.add_argument("--deqp-pipeline-file",			type=pathlib.Path,				default=None)
			self.add_argument("--deqp-pipeline-logfile",		type=pathlib.Path,				default=None)
			self.add_argument("--deqp-pipeline-prefix",			type=pathlib.Path,				default=None)
			self.add_argument("--deqp-server-address",											default=None)
			self.add_argument("--deqp-subprocess-test-count",	type=int,						default=65536)
			self.add_argument("--deqp-subprocess-cfg-file",		type=pathlib.Path,				default=None)
			self.add_argument("--deqp-subprocess",				choices=["enable", "disable"],	default="disable")
			self.add_argument("--deqp-vk-library-path",			type=pathlib.Path,				default=None)

class Verification:
	def __init__(self, packagePath, ctsPath, api, version, releaseTag):
		self.packagePath	= packagePath
		self.ctsPath		= ctsPath
		self.api			= api
		self.version		= version
		self.releaseTag		= releaseTag
		self.cmdParser		= self._getCommandParser()

	def _getCommandParser(self):
		parser = None
		if self.api == "VK" or self.api == "VKSC":
			parser = CommandLineParserVk(self.api)
		return parser

def beginsWith (str, prefix):
	return str[:len(prefix)] == prefix

def readFile (filename):
	f = open(filename, 'rb')
	data = f.read()
	f.close()
	return data

def untarPackage(report, pkgFile, dst):
	report.message("Unpacking to %s ..." % str(dst), pkgFile)
	try:
		tar = tarfile.open(pkgFile)
		tar.extractall(dst)
		tar.close()
	except Exception as e:
		report.failure("Failed to unpack. Exception %s raised" % str(e), pkgFile)
		return False
	report.message("Unpacking done.", pkgFile)
	return True

g_workDirStack = []

def pushWorkingDir (path):
	oldDir = os.getcwd()
	os.chdir(path)
	g_workDirStack.append(oldDir)

def popWorkingDir ():
	assert len(g_workDirStack) > 0
	newDir = g_workDirStack[-1]
	g_workDirStack.pop()
	os.chdir(newDir)

def git (*args):
	process = subprocess.Popen(['git'] + list(args), stdout=subprocess.PIPE)
	output = process.communicate()[0]
	if process.returncode != 0:
		raise Exception("Failed to execute '%s', got %d" % (str(args), process.returncode))
	return output.decode('utf-8', 'ignore')

def fetchSources(script):
	args	= [[],
			   ['--protocol=ssh'],
			   ['--protocol=https'],
			   ['--insecure'],
			   ['--protocol=ssh', '--insecure'],
			   ['--protocol=https', '--insecure']]

	returncode = subprocess.call([sys.executable, script, '--clean'])
	if returncode != 0:
		raise Exception("Failed to clean external sources, got %d" % (process.returncode))

	success = False

	for arg in args:
		params = [sys.executable, script]
		params.extend(arg)
		returncode = subprocess.call(params)
		if returncode == 0:
			success = True
			break

	if not success:
		raise Exception("Could not fetch sources")

def cloneCTS(dest):
	repos		= ['ssh://gerrit.khronos.org:29418/vk-gl-cts',
				   'https://github.com/KhronosGroup/VK-GL-CTS',
				   'git@gitlab.khronos.org:Tracker/vk-gl-cts.git',
				   'https://gitlab.khronos.org/Tracker/vk-gl-cts.git',
				   'https://gerrit.khronos.org/a/vk-gl-cts']
	success		= False
	print(dest)
	for repo in repos:
		try:
			git('clone', repo, dest)
		except Exception as e:
			print("Failed to clone %s. Trying the next repo." % repo)
		else:
			success = True
			break

	if not success:
		print("Failed to clone VK-GL-CTS. Verification will now stop.")
		sys.exit(RETURN_CODE_ERR)

def validateSource(ctsPath):
	if ctsPath == None:
		ctsPath = os.path.join(tempfile.gettempdir(), "VK-GL-CTS")
		cloneCTS(ctsPath)

	pushWorkingDir(ctsPath)
	try:
		result = git('rev-parse', '--is-inside-work-tree')
	except:
		sys.exit(RETURN_CODE_ERR)
	else:
		if result == "false":
			print("Path to VK-GL-CTS is not a git tree. Verification will now stop.")
			sys.exit(RETURN_CODE_ERR)
	popWorkingDir()

	return ctsPath

def checkoutReleaseTag(report, releaseTag):
	success = False
	try:
		git('checkout', releaseTag)
	except:
		report.failure("Failed to checkout release tag %s" % releaseTag)
	else:
		success = True
	return success

def applyPatch(report, patch):
	success = False
	try:
		git('apply', '--whitespace=nowarn', patch)
	except:
		report.failure("Failed to apply patch %s" % patch)
	else:
		success = True
	return success

def readTestLog (report, filename):
	parser = BatchResultParser(report)
	return parser.parseFile(filename)

def verifyFileIntegrity(report, filename, info, gitSHA):

	anyError = False
	report.message("Verifying file integrity.", filename)

	report.message("Verifying sessionInfo")

	releaseNameKey	= "releaseName"
	if releaseNameKey not in info:
		anyError |= True
		report.failure("Test log is missing %s" % releaseNameKey)
	else:
		sha1 = info[releaseNameKey]
		hashDigits = ''
		if sha1.startswith('git-'):
			# Keep whatever comes after "git-", containing the git hash.
			hashDigits = sha1[4:]
		elif '-' in sha1:
			# It may be something like vulkan-cts-1.3.6.0-0-g6ca63e81c
			# We have to extract "6ca63e81c" (note we skip the g)
			hashDigits = sha1.split('-')[-1][1:]
		else:
			hashDigits = sha1
		if gitSHA.startswith(hashDigits):
			report.passed("Test log %s matches the HEAD commit from git log: %s" % (releaseNameKey, gitSHA))
		else:
			anyError |= True
			report.failure("Test log %s doesn't match the HEAD commit from git log: %s" % (releaseNameKey, gitSHA))

	releaseIdKey	= "releaseId"
	if releaseIdKey not in info:
		anyError |= True
		report.failure("Test log is missing %s" % releaseIdKey)
	else:
		sha1 = info[releaseIdKey]
		if sha1 == '0x' + gitSHA[0:8]:
			report.passed("Test log %s matches the HEAD commit from git log: %s" % (releaseIdKey, gitSHA))
		else:
			anyError |= True
			report.failure("Test log %s doesn't match the HEAD commit from git log: %s" % (releaseIdKey, gitSHA))
	return anyError

def isSubmissionSupported(apiType):
	if apiType == "VK":
		return True
	if apiType == "VKSC":
		return True
	if apiType == "GL":
		return True
	if apiType == "ES":
		return True
	return False

def validateTestCasePresence(report, mustpass, results):
	# Verify that all results are present and valid
	anyError = False
	resultOrderOk = True
	caseNameToResultNdx = {}
	for ndx in range(len(results)):
		result = results[ndx]
		if not result in caseNameToResultNdx:
			caseNameToResultNdx[result.name] = ndx
		else:
			report.failure("Multiple results for " + result.name)
			anyError |= True

	failNum = 0
	for ndx in range(len(mustpass.cases)):
		caseName = mustpass.cases[ndx]

		if caseName in caseNameToResultNdx:
			resultNdx	= caseNameToResultNdx[caseName]
			result		= results[resultNdx]

			if resultNdx != ndx:
				resultOrderOk = False

			if not result.statusCode in ALLOWED_STATUS_CODES:
				report.failure(result.name + ": " + result.statusCode)
				anyError |= True
			if result.statusCode == StatusCode.WAIVED:
				report.warning(result.name + ": " + result.statusCode)
		else:
			if failNum < 21:
				report.failure("Missing result for " + caseName)
				failNum += 1
			anyError |= True

	if failNum >= 21:
		report.message("More missing results found but only first 20 are reported")

	return anyError, resultOrderOk

def verifyTestLog (report, package, mustpass, fractionMustpass, gitSHA):
	# Mustpass case names must be unique
	assert len(mustpass.cases) == len(set(mustpass.cases))
	if fractionMustpass != None:
		assert len(fractionMustpass.cases) == len(set(fractionMustpass.cases))

	anyError		= False
	for key, filesList in package.testLogs.items():
		totalResults	= []
		isFractionResults = (len(filesList) > 1)

		addFullResults = True
		for testLogFile in filesList:
			filename = os.path.join(package.basePath, testLogFile)
			report.message("Reading results.", filename)
			results, info	= readTestLog(report, filename)
			anyError |= verifyFileIntegrity(report, filename, info, gitSHA)

			if isFractionResults:
				report.message("Verifying %s results." % (fractionMustpass.basename), filename)
				anyErrorFract, resultOrderOk = validateTestCasePresence(report, fractionMustpass, results)

				if anyErrorFract:
					report.failure("Verification of %s results FAILED" % (fractionMustpass.basename), filename)
					anyError |= anyErrorFract
				else:
					report.passed("Verification of %s results PASSED" % (fractionMustpass.basename), filename)

			if addFullResults:
				totalResults += results
				addFullResults = False
			else:
				results = [r for r in results if r.name not in fractionMustpass.cases]
				totalResults += results

		report.message("Verifying %s results." % (mustpass.basename))
		anyErrorMustpass, resultOrderOk = validateTestCasePresence(report, mustpass, totalResults)

		# Verify number of results
		if len(totalResults) != len(mustpass.cases):
			report.failure("Wrong number of test results, expected %d, found %d" % (len(mustpass.cases), len(totalResults)))
			anyErrorMustpass |= True

		if anyErrorMustpass:
			report.failure("Verification of %s results FAILED" % (mustpass.basename))
			anyError |= anyErrorMustpass
		else:
			report.passed("Verification of %s results PASSED" % (mustpass.basename))

	return anyError

def verifyTestLogES (report, filename, mustpass, gitSHA):
	# Mustpass case names must be unique
	assert len(mustpass.cases) == len(set(mustpass.cases))

	report.message("Reading results.", filename)
	results, info	= readTestLog(report, filename)
	anyError		= False
	resultOrderOk	= True

	anyError |= verifyFileIntegrity(report, filename, info, gitSHA)

	# Verify number of results
	if len(results) != len(mustpass.cases):
		report.failure("Wrong number of test results, expected %d, found %d" % (len(mustpass.cases), len(results)), filename)
		anyError |= True

	anyErrorMustpass, resultOrderOk = validateTestCasePresence(report, mustpass, results)

	if len(results) == len(mustpass.cases) and not resultOrderOk:
		report.failure("Results are not in the expected order", filename)
		anyErrorMustpass |= True

	if anyErrorMustpass:
		report.failure("Verification of test results FAILED", filename)
		anyError |= anyErrorMustpass
	else:
		report.passed("Verification of test results PASSED", filename)

	return anyError
