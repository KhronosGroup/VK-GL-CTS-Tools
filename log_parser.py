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

import argparse
import shlex
import time
import xml.dom.minidom
import re

class StatusCode:
	PASS					= 'Pass'
	FAIL					= 'Fail'
	WAIVED  				= 'Waiver'
	QUALITY_WARNING			= 'QualityWarning'
	COMPATIBILITY_WARNING	= 'CompatibilityWarning'
	PENDING					= 'Pending'
	NOT_SUPPORTED			= 'NotSupported'
	RESOURCE_ERROR			= 'ResourceError'
	INTERNAL_ERROR			= 'InternalError'
	CRASH					= 'Crash'
	TIMEOUT					= 'Timeout'
	WAIVER					= 'Waiver'
	PARSE_ERROR				= 'ParseError'

	STATUS_CODE_SET			= {
		PASS,
		FAIL,
		WAIVED,
		QUALITY_WARNING,
		COMPATIBILITY_WARNING,
		PENDING,
		NOT_SUPPORTED,
		RESOURCE_ERROR,
		INTERNAL_ERROR,
		CRASH,
		TIMEOUT,
		WAIVER,
		PARSE_ERROR
		}

	@staticmethod
	def isValid (code):
		return code in StatusCode.STATUS_CODE_SET

class TestCaseResult:
	def __init__ (self, name, statusCode, statusDetails, log):
		self.name			= name
		self.statusCode		= statusCode
		self.statusDetails	= statusDetails
		self.log			= log

	def __str__ (self):
		return "%s: %s (%s)" % (self.name, self.statusCode, self.statusDetails)

class ParseError(Exception):
	def __init__ (self, filename, line, message):
		self.filename	= filename
		self.line		= line
		self.message	= message

	def __str__ (self):
		return "%s:%d: %s" % (self.filename, self.line, self.message)

def splitContainerLine (line):
	return shlex.split(line)

def getNodeText (node):
	rc = []
	for node in node.childNodes:
		if node.nodeType == node.TEXT_NODE:
			rc.append(node.data)
	return ''.join(rc)

class BatchResultParser:
	def __init__ (self, report):
		self.report = report
		self.lastStatusPrint = time.time()

	def parseFile (self, filename):
		self.init(filename)

		f = open(filename, 'rb')
		for line in f:
			line = line.decode('utf-8', 'ignore')
			self.parseLine(line)
			self.curLine += 1
		f.close()

		return self.testCaseResults, self.sessionInfo

	def init (self, filename):
		# Results
		self.sessionInfo		= {}
		self.testCaseResults	= []

		# State
		self.curResultText		= None
		self.curCaseName		= None

		# Error context
		self.curLine			= 1
		self.filename			= filename

	def parseLine (self, line):
		if len(line) > 0 and line[0] == '#':
			self.parseContainerLine(line)
		else:
			if len(line) > 0 and line.startswith("<TestCaseResult"):
				pattern = r'CasePath=\"([^\"]+)\"'
				match = re.search(pattern, line)
				if not match or self.curCaseName != None:
					self.parseError("Invalid <TestCaseResult...\n" + line + "\n")
				self.curCaseName	= match.group(1)
				self.curResultText = line
			elif len(line) > 0 and line.startswith("</TestCaseResult>"):
				if self.curCaseName == None:
					self.parseError("Invalid </TestCaseResult>")
				self.curResultText += line
				self.parseTestCaseResult(self.curCaseName, self.curResultText)
				self.curCaseName	= None
				self.curResultText	= None
			elif self.curResultText != None:
				self.curResultText += line

	def parseContainerLine (self, line):
		args = splitContainerLine(line)
		if args[0] == "#sessionInfo":
			if len(args) < 3:
				print(args)
				self.parseError("Invalid #sessionInfo")
			self.sessionInfo[args[1]] = ' '.join(args[2:])
		elif args[0] == "#beginSession" or args[0] == "#endSession":
			pass
		elif args[0] == "#beginTestCaseResult":
			pass # Superseded by XML
		elif args[0] == "#endTestCaseResult":
			pass # Superseded by XML
		elif args[0] == "#terminateTestCaseResult":
			pass # Superseded by XML
		else:
			# Assume this is result text
			if self.curResultText != None:
				self.curResultText += line

	def parseTestCaseResult (self, name, log):
		try:
			# The XML parser has troubles with invalid characters deliberately included in the shaders.
			# This line removes such characters before calling the parser
			log = bytes(log, 'utf-8').decode('utf-8', 'ignore')
			doc = xml.dom.minidom.parseString(log)
			resultItems = doc.getElementsByTagName('Result')
			if len(resultItems) != 1:
				self.parseError("Expected 1 <Result>, found %d" % len(resultItems))

			statusCode		= resultItems[0].getAttributeNode('StatusCode').nodeValue
			statusDetails	= getNodeText(resultItems[0])
		except Exception as e:
			statusCode		= StatusCode.PARSE_ERROR
			statusDetails	= "XML parsing failed: %s" % str(e)

		self.testCaseResults.append(TestCaseResult(name, statusCode, statusDetails, log))
		now = time.time()
		if now - self.lastStatusPrint > 60:
			self.lastStatusPrint = now
			self.report.message('Still reading results (%u so far)' % len(self.testCaseResults))

	def parseError (self, message):
		raise ParseError(self.filename, self.curLine, message)

class CommandLineParser(argparse.ArgumentParser):
	def exit(self, status=0, message=None):
		if message != None:
			raise Exception(message)
		raise Exception("invalid command line")

	def error(self, message):
		raise Exception(message)

	def parse_args(self, args=None, namespace=None):
		args, argv = self.parse_known_args(args, namespace)
		if argv:
			self.error("arguments not allowed for submission: %s" % (' '.join(argv)))
		return args
