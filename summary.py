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

import xml.dom.minidom
from report import *

class TestRunSummary:
	def __init__ (self, type, isConformant, configLogFilename, runLogFilenames, runLogAndCaselist):
		self.type				= type
		self.isConformant		= isConformant
		self.configLogFilename	= configLogFilename
		self.runLogFilenames	= runLogFilenames
		self.runLogAndCaselist	= runLogAndCaselist

def parseRunSummary (report, filename):
	doc = xml.dom.minidom.parse(filename)
	summary = doc.documentElement
	if summary.localName != "Summary":
		raise Exception("Document element is not <Summmary>")

	type			= summary.getAttributeNode("Type").nodeValue
	conformantNode	= summary.getAttributeNode("Conformant")
	isConformant	= True
	if conformantNode:
		isConformant	= conformantNode.nodeValue == "True"
	else:
		report.warning("Conformant attr not found")

	configRuns		= doc.getElementsByTagName("Configs")
	if len(configRuns) != 1:
		raise Exception("Excepted one <Configs> element, found %d" % len(configRuns))

	runLogFilenames = []
	runLogAndCaselist = {}
	runFiles		= doc.getElementsByTagName("TestRun")
	for n in runFiles:
		runLog = n.getAttributeNode("FileName").nodeValue
		runLogFilenames.append(runLog)
		cmdLine = n.getAttributeNode("CmdLine").nodeValue
		caseList = None
		for words in cmdLine.split():
			if "deqp-caselist" in words:
				caseList = words.split("=")[1]
				caseList = caseList[len("gl_cts/"):]
		runLogAndCaselist[runLog] = caseList

	return TestRunSummary(type, isConformant, configRuns[0].getAttributeNode("FileName").nodeValue, runLogFilenames, runLogAndCaselist)
