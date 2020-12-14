# -*- coding: utf-8 -*-

#-------------------------------------------------------------------------
# VK-GL-CTS Conformance Submission Verification
# ---------------------------------------------
#
# Copyright (c) 2020 The Khronos Group Inc.
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
		report.failure("Confomant configs reported for %s and %s do not match" % (baseKey,cmpKey))

def verifyConfigFile (report, filename, type):
	caseNames = getConfigCaseName(type)

	parser					= BatchResultParser()
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

def verifyMustpassCases(report, package, mustpassCases, type):
	messages = []
	apiToTestBase = { "es32" : ["gles32", "gles31", "gles3", "gles2", "egl"],
				  "es31" : ["gles31", "gles3", "gles2", "egl"],
				  "es3"  : ["gles3", "gles2", "egl"],
				  "es2"  : ["gles2", "egl"],
				  "gl46" : ["gl46"],
				  "gl45" : ["gl45"],
				  "gl44" : ["gl44"],
				  "gl43" : ["gl43"],
				  "gl42" : ["gl42"],
				  "gl41" : ["gl41"],
				  "gl40" : ["gl40"],
				  "gl33" : ["gl33"],
				  "gl32" : ["gl32"],
				  "gl31" : ["gl31"],
				  "gl30" : ["gl30"],
				  }

	apiToTestNoCTX = { "gl46" : ["gl45", "gl43", "gl40", "gl30"],
					   "gl45" : ["gl45", "gl43", "gl40", "gl30"],
					   "gl44" : ["gl40", "gl30"],
					   "gl43" : ["gl40", "gl30"],
					   "gl42" : ["gl40", "gl30"],
					   "gl41" : ["gl40", "gl30"],
					   "gl40" : ["gl40", "gl30"],
					   "gl33" : ["gl30"],
					   "gl32" : ["gl30"],
					   "gl31" : ["gl30"],
					   "gl30" : ["gl30"],
					}
	for mustpass in mustpassCases:
		mustpassXML = os.path.join(mustpass, "mustpass.xml")
		doc = xml.dom.minidom.parse(mustpassXML)
		apiToTest = apiToTestBase
		if "GL NoContext" in doc.getElementsByTagName("TestPackage")[0].getAttributeNode("name").nodeValue:
			apiToTest = apiToTestNoCTX
		testConfigs = doc.getElementsByTagName("Configuration")
		# check that all configs that must be tested are present
		for testConfig in testConfigs:
			caseListFile = testConfig.getAttributeNode("caseListFile").nodeValue
			# identify APIs that must be tested for the given type
			apis = apiToTest[type]
			# identify API tested by the current config
			configAPI = caseListFile.split('-')[0]
			if configAPI in apis:
				# the API in this config is expected to be tested
				mustTest = True
			else:
				mustTest = False
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
			if len(matches) == 0 and mustTest == True:
					conformOs = testConfig.getAttributeNode("os").nodeValue
					txt = "Configuration %s %s was not executed" % (caseListFile, cmdLine)
					if conformOs == "any" or (package.conformOs != None and conformOs in package.conformOs.lower()):
						report.failure(txt)
					else:
						report.warning(txt)
			elif len(matches) != 0 and mustTest == False:
				report.failure("Configuration %s %s was not expected to be tested but present in cts-run-summary.xml" % (caseListFile, cmdLine))

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
		success, mustpass = readMustpass(report, mustpassFile)
		if success == True:
			verifyTestLogES(report, os.path.join(package.basePath, runLog), mustpass, gitSHA)

	verifyMustpassCases(report, package, mustpassCases, summary.type)

def verify_es (report, verfification, package, gitSHA):
	verifyTestLogs(report, package, gitSHA, verfification.ctsPath)
