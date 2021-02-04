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
import sys
import datetime

RETURN_CODE_ERR		= -1
RETURN_CODE_FAIL	= -2
RETURN_CODE_NSUP	= -3

class ReportMessage:
	TYPE_PASS	= 0
	TYPE_FAIL	= 1
	TYPE_WARN	= 2
	TYPE_MESG	= 3
	TYPE_NSUP	= 4
	TYPE_TITL	= 5
	TYPE_STTL	= 6
	TYPE_CMSG	= 7

	def __init__ (self, type, filename, message):
		self.type		= type
		self.filename	= filename
		self.message	= message

	def __str__ (self):
		prefix = {self.TYPE_PASS: "PASS: ",
				  self.TYPE_FAIL: "FAIL: ",
				  self.TYPE_WARN: "WARN: ",
				  self.TYPE_MESG: "MESG: ",
				  self.TYPE_NSUP: "NSUP: ",
				  self.TYPE_TITL: "",
				  self.TYPE_STTL: "",
				  self.TYPE_CMSG: ""}
		if self.filename != None:
			msg = prefix[self.type] + os.path.basename(self.filename) + ": " + self.message
		else:
			msg = prefix[self.type] + self.message
		return msg

	def md(self):
		prefix = {self.TYPE_PASS: '<span style="color:green">PASS</span>: ',
				  self.TYPE_FAIL: '<span style="color:red">FAIL</span>: ',
				  self.TYPE_WARN: '<span style="color:orange">WARN</span>: ',
				  self.TYPE_MESG: '<span style="color:blue">MESG</span>: ',
				  self.TYPE_NSUP: '<span style="color:lime">NSUP</span>: ',
				  self.TYPE_TITL: '\n## ',
				  self.TYPE_STTL: '\n### ',
				  self.TYPE_CMSG: '\n```\n'}
		postfix = {self.TYPE_PASS: '',
				   self.TYPE_FAIL: '',
				   self.TYPE_WARN: '',
				   self.TYPE_MESG: '',
				   self.TYPE_NSUP: '',
				   self.TYPE_TITL: '',
				   self.TYPE_STTL: '',
				   self.TYPE_CMSG: '\n```\n'}
		if self.filename != None:
			msg = prefix[self.type] + os.path.basename(self.filename) + ": " + self.message + postfix[self.type]
		else:
			msg = prefix[self.type] + self.message + postfix[self.type]
		return msg

class Report:
	def __init__(self, verbose, output):
		self.messages	= []
		self.isVerbose	= verbose
		self.output		= output

	def verbose(self, msg):
		if self.isVerbose:
			sys.stdout.write(str(msg) + '\n')
			sys.stdout.flush()
		return

	def reportTitle(self, submissionId):
		message = "Automated verification report"
		if submissionId:
			message += " for submission #%s" % submissionId
		reportMsg = ReportMessage(ReportMessage.TYPE_TITL, None, message)
		self.verbose(reportMsg)
		return self.messages.append(reportMsg)

	def reportSubTitle(self, message):
		reportMsg = ReportMessage(ReportMessage.TYPE_STTL, None, message)
		self.verbose(reportMsg)
		return self.messages.append(reportMsg)

	def fmtmessage(self, message):
		reportMsg = ReportMessage(ReportMessage.TYPE_CMSG, None, message)
		self.verbose(reportMsg)
		return self.messages.append(reportMsg)

	def failure(self, message, filename = None):
		reportMsg = ReportMessage(ReportMessage.TYPE_FAIL, filename, message)
		self.verbose(reportMsg)
		return self.messages.append(reportMsg)

	def passed(self, message, filename = None):
		reportMsg = ReportMessage(ReportMessage.TYPE_PASS, filename, message)
		self.verbose(reportMsg)
		return self.messages.append(reportMsg)

	def warning(self, message, filename = None):
		reportMsg = ReportMessage(ReportMessage.TYPE_WARN, filename, message)
		self.verbose(reportMsg)
		return self.messages.append(reportMsg)

	def message(self, message, filename = None):
		reportMsg = ReportMessage(ReportMessage.TYPE_MESG, filename, message)
		self.verbose(reportMsg)
		return self.messages.append(reportMsg)

	def legend(self):
		msg = []
		msg.append(ReportMessage(ReportMessage.TYPE_STTL, None, "Legend"))
		msg.append(ReportMessage(ReportMessage.TYPE_MESG, None, "Informative message. Doesn't affect verification status."))
		msg.append(ReportMessage(ReportMessage.TYPE_WARN, None, "Warning found in the package. Manual review required."))
		msg.append(ReportMessage(ReportMessage.TYPE_FAIL, None, "Error found in the package. Verification step failed."))
		msg.append(ReportMessage(ReportMessage.TYPE_PASS, None, "Verification step succeeded."))
		output = '\n'.join(m.md() + '<br>' for m in msg)
		return output

	def generate(self, returnCode = None):
		fails			= len([m for m in self.messages if m.type == ReportMessage.TYPE_FAIL])
		warnings		= len([m for m in self.messages if m.type == ReportMessage.TYPE_WARN])

		failEpl			= 'Recorded errors:   %s\n' % fails
		warnEpl			= 'Recorded warnings: %s\n' % warnings
		warnMsg			= 'Warnings detected. Please review manually.'
		failMsg			= 'Errors detected. Verification FAILED.'
		passMsg			= 'No errors or warnings detected. Verification PASSED.'
		timeStamp		= datetime.datetime.now().isoformat()
		summary			= ''

		summary		+= '\n'
		summary		+= '\n' + failEpl + '<br>'
		summary		+= '\n' + warnEpl + '<br>'
		summary		+= '\n'

		if warnings > 0 :
			summary	+= '<span style="color:orange">' + warnMsg + '</span>\n<br>'
		if fails > 0 :
			summary	+= '<span style="color:red">' + failMsg + '</span>\n<br>'
		if fails == 0 and warnings == 0:
			summary	+= '<span style="color:green">' + passMsg + '</span>\n<br>'

		if not self.isVerbose:
			reportStdout	= '\n'.join(str(m) for m in self.messages)
			print(reportStdout)

		if self.output != None:
			reportMD = ""
			for m in self.messages:
				if m.type != ReportMessage.TYPE_CMSG and m.type != ReportMessage.TYPE_TITL and m.type != ReportMessage.TYPE_STTL:
					reportMD	+= '\n'+ m.md().replace('_', '\_') + '<br>'
				else:
					reportMD	+= '\n'+ m.md() + '\n'
				if m.type == ReportMessage.TYPE_TITL:
					reportMD += "\n\n### Summary"
					reportMD += summary

			reportMD += '\n' + self.legend()

			reportMD += "\n\n### Timestamps"
			reportMD += "\n_This report is generated on %s._" % timeStamp

			f = open(self.output, 'w')
			f.write(reportMD)
			f.close()

		print('\n' + '=' * 54)
		print('\n' + failEpl + warnEpl)
		if warnings > 0 :
			print(warnMsg)
		if fails > 0 :
			returnCode = -1
			print(failMsg)
		if fails == 0 and warnings == 0:
			print(passMsg)
		print('\n' + '=' * 54)

		return
