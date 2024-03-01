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
import os
from report import *
from summary import *
from log_parser import *
from utils import *

def getConfigCaseName (type):
	configs = { "es32" : ["CTS-Configs.es32", "CTS-Configs.es31", "CTS-Configs.es3", "CTS-Configs.es2"],
				"es31" : ["CTS-Configs.es31", "CTS-Configs.es3", "CTS-Configs.es2"],
				"es3"  : ["CTS-Configs.es3", "CTS-Configs.es2"],
				"es2"  : ["CTS-Configs.es2"],
				"gl46" : ["CTS-Configs.gl46", "CTS-Configs.gl45", "CTS-Configs.gl44", "CTS-Configs.gl43", "CTS-Configs.gl42",  "CTS-Configs.gl41", "CTS-Configs.gl40", "CTS-Configs.gl33", "CTS-Configs.gl32", "CTS-Configs.gl31", "CTS-Configs.gl30"],
				"gl45" : ["CTS-Configs.gl45", "CTS-Configs.gl44", "CTS-Configs.gl43", "CTS-Configs.gl42",  "CTS-Configs.gl41", "CTS-Configs.gl40", "CTS-Configs.gl33", "CTS-Configs.gl32", "CTS-Configs.gl31", "CTS-Configs.gl30"],
				"gl44" : ["CTS-Configs.gl44", "CTS-Configs.gl43", "CTS-Configs.gl42",  "CTS-Configs.gl41", "CTS-Configs.gl40", "CTS-Configs.gl33", "CTS-Configs.gl32", "CTS-Configs.gl31", "CTS-Configs.gl30"],
				"gl43" : ["CTS-Configs.gl43", "CTS-Configs.gl42",  "CTS-Configs.gl41", "CTS-Configs.gl40", "CTS-Configs.gl33", "CTS-Configs.gl32", "CTS-Configs.gl31", "CTS-Configs.gl30"],
				"gl42" : ["CTS-Configs.gl42", "CTS-Configs.gl41", "CTS-Configs.gl40", "CTS-Configs.gl33", "CTS-Configs.gl32", "CTS-Configs.gl31", "CTS-Configs.gl30"],
				"gl41" : ["CTS-Configs.gl41", "CTS-Configs.gl40", "CTS-Configs.gl33", "CTS-Configs.gl32", "CTS-Configs.gl31", "CTS-Configs.gl30"],
				"gl40" : ["CTS-Configs.gl40", "CTS-Configs.gl33", "CTS-Configs.gl32", "CTS-Configs.gl31", "CTS-Configs.gl30"],
				"gl33" : ["CTS-Configs.gl33", "CTS-Configs.gl32", "CTS-Configs.gl31", "CTS-Configs.gl30"],
				"gl32" : ["CTS-Configs.gl32", "CTS-Configs.gl31", "CTS-Configs.gl30"],
				"gl31" : ["CTS-Configs.gl31", "CTS-Configs.gl30"],
				"gl30" : ["CTS-Configs.gl30"],
				}
	return configs[type]

def retrieveReportedConfigs(caseName, log):
	doc				= xml.dom.minidom.parseString(log)
	sectionItems	= doc.getElementsByTagName('Section')
	sectionName		= None

	configs = []
	for sectionItem in sectionItems:
		sectionName	= sectionItem.getAttributeNode('Name').nodeValue
		if sectionName == "Configs":
			assert len(configs) == 0
			textItems = sectionItem.getElementsByTagName('Text')
			for textItem in textItems:
				configs.append(getNodeText(textItem))
	res = {caseName : configs}
	return res

def compareConfigs(report, filename, baseConfigs, cmpConfigs):
	messages = []
	assert len(list(baseConfigs.keys())) == 1
	assert len(list(cmpConfigs.keys())) == 1
	baseKey = list(baseConfigs.keys())[0]
	cmpKey = list(cmpConfigs.keys())[0]

	if baseConfigs[baseKey] != cmpConfigs[cmpKey]:
		report.failure("Conformant configs reported for %s and %s do not match" % (baseKey,cmpKey))

def verifyConfigFile (report, filename, type):
	caseNames = getConfigCaseName(type)

	parser					= BatchResultParser(report)
	results, sessionInfo	= parser.parseFile(filename)
	baseConfigs				= None

	for caseName in caseNames:
		caseResult	= None
		report.message("Verifying %s in %s" % (caseName, filename))
		for result in results:
			if result.name == caseName:
				caseResult = result
				break;
		if caseResult == None:
			report.failure("Missing %s" % caseName)
		else:
			configs = retrieveReportedConfigs(caseName, result.log)
			if baseConfigs == None:
				baseConfigs = configs
			else:
				compareConfigs(report, filename, baseConfigs, configs)
			if caseResult.statusCode in ALLOWED_STATUS_CODES:
				report.passed("%s" % caseResult)
			else:
				report.failure("%s failed" % caseResult)

def getConfigVersion(report, api):
	m = re.match("gl([0-9]+)", api)
	if m:
		return ("gl", int(m.group(1)))

	m = re.match(".*es([0-9]+)", api)
	if m:
		# eg. gles3 == version 30
		version = int(m.group(1))
		if version < 10:
			version = version * 10
		return ("gles", version)

	if api == "egl":
		return ("egl", 0)

	report.failure("Unknown API version %s, cannot automatically verify" % (api))
	return ("", 0)

def verifyMustpassCases(report, package, mustpassCases, type):
	typeApi, typeVersion = getConfigVersion(report, type)

	for mustpass in mustpassCases:
		mustpassXML = os.path.join(mustpass, "mustpass.xml")
		doc = xml.dom.minidom.parse(mustpassXML)
		configs = doc.getElementsByTagName("Configuration")

		testConfigs = []
		testConfigVersion = 0

		if "GL NoContext" in doc.getElementsByTagName("TestPackage")[0].getAttributeNode("name").nodeValue or typeApi != "gl":
			# No context and non-gl tests all configs less than or equal to type version
			for config in configs:
				caseListFile = config.getAttributeNode("caseListFile").nodeValue
				_, configVersion = getConfigVersion(report, caseListFile.split('-')[0])
				if configVersion <= typeVersion:
					testConfigs.append(config)
		else:
			# For GL check for the configs which must be tested (largest version less than "type")
			for config in configs:
				caseListFile = config.getAttributeNode("caseListFile").nodeValue
				_, configVersion = getConfigVersion(report, caseListFile.split('-')[0])
				if configVersion == testConfigVersion:
					testConfigs.append(config)
				elif configVersion > testConfigVersion and configVersion <= typeVersion:
					testConfigVersion = configVersion
					testConfigs = [config]

		# Check that all of the test configs are present
		totalMatches = []
		for testConfig in testConfigs:
			caseListFile = testConfig.getAttributeNode("caseListFile").nodeValue
			pattern = "config-" + os.path.splitext(caseListFile)[0] + "-cfg-[0-9]*"+"-run-[0-9]*"
			cmdLine = testConfig.getAttributeNode("commandLine").nodeValue
			cfgItems = {'height':None, 'width':None, 'seed':None, 'rotation':None}
			for arg in cmdLine.split():
				val = arg.split('=')[1]
				if "deqp-surface-height" in arg:
					cfgItems['height'] = val
				elif "deqp-surface-width" in arg:
					cfgItems['width'] = val
				elif "deqp-base-seed" in arg:
					cfgItems['seed'] = val
				elif "deqp-screen-rotation" in arg:
					cfgItems['rotation'] = val
			pattern += "-width-" + cfgItems['width'] + "-height-" + cfgItems['height']
			if cfgItems['seed'] != None:
				pattern += "-seed-" + cfgItems['seed']
			pattern += ".qpa"
			p = re.compile(pattern)
			matches = [m for l in mustpassCases[mustpass] for m in (p.match(l),) if m]

			if len(matches) == 0:
					conformOs = testConfig.getAttributeNode("os").nodeValue
					txt = "Configuration %s %s %s was not executed" % (conformOs, caseListFile, cmdLine)
					if conformOs == "any" or (package.conformOs != None and conformOs in package.conformOs.lower()):
						report.failure(txt)
					else:
						report.warning(txt + " due to N/A on OS (%s)" % ("None" if package.conformOs == None else package.conformOs))
			else:
				totalMatches.extend([m.string for m in matches])

		extraConfigs = list(set(mustpassCases[mustpass]) - set(totalMatches))
		for config in extraConfigs:
			report.failure("Configuration %s was not expected to be tested but present in cts-run-summary.xml" % (config))

def verifyTestLogs(report, package, gitSHA, ctsPath):
	if package.summary == None:
		report.failure("The package is missing cts-run-summary.xml")
		return
	summary	= parseRunSummary(os.path.join(package.basePath, package.summary))
	mustpassDirs = []

	# Check Conformant attribute
	if not summary.isConformant:
		report.failure("Runner reported conformance failure (Conformant=\"False\" in <Summary>)")

	# Verify config list
	verifyConfigFile(report, os.path.join(package.basePath, summary.configLogFilename), summary.type)

	mustpassCases = {}
	# Verify that all run files passed
	for runLog in summary.runLogAndCaselist:
		mustpassFile = os.path.join(ctsPath, "external", "openglcts", summary.runLogAndCaselist[runLog])
		key = os.path.dirname(mustpassFile)
		if key in mustpassCases:
			mpCase = mustpassCases[key]
		else:
			mpCase = []
		mpCase.append(runLog)
		mustpassCases[os.path.dirname(mustpassFile)] = mpCase
		mustpass = Mustpass(mustpassFile)
		if mustpass.read(report):
			verifyTestLogES(report, os.path.join(package.basePath, runLog), mustpass, gitSHA)

	verifyMustpassCases(report, package, mustpassCases, summary.type)

def verify_es (report, verfification, package, gitSHA):
	verifyTestLogs(report, package, gitSHA, verfification.ctsPath)
