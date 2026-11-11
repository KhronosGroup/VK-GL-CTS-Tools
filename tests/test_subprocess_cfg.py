# -*- coding: utf-8 -*-

#-------------------------------------------------------------------------
# VK-GL-CTS Conformance Submission Verification
# ---------------------------------------------
#
# Copyright 2026 The Khronos Group Inc.
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

# Tests for --deqp-subprocess-cfg-file handling in getPackageDescription
# (Vulkan SC): the cfg file may be shared by all fractions of a submission.
# Run from the repository root with: python3 -m unittest discover -s tests

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from package import getPackageDescription
from report import Report, ReportMessage
from utils import Verification

MANDATORY_ARGS = "--deqp-caselist-file=vksc-default.txt --deqp-log-images=disable --deqp-log-shader-sources=disable"

class SubprocessCfgPackageTest(unittest.TestCase):
	# Fake Vulkan SC submission package with one test log per fraction; each
	# log holds only the session info line that getPackageDescription reads.

	def setUp (self):
		self.tmp = tempfile.TemporaryDirectory()
		self.path = self.tmp.name

	def tearDown (self):
		self.tmp.cleanup()

	def writeFile (self, name, text = ""):
		with open(os.path.join(self.path, name), "w") as f:
			f.write(text)

	def writeLog (self, index, count, cfg):
		args = "%s --deqp-fraction=%d,%d --deqp-fraction-mandatory-caselist-file=vksc-fraction-mandatory-tests.txt --deqp-subprocess-cfg-file=%s" % (MANDATORY_ARGS, index, count, cfg)
		self.writeFile("TestResults-%d-of-%d.qpa" % (index, count), "#sessionInfo commandLineParameters \"%s\"\n" % args)

	def describe (self):
		report = Report(False, None)
		package = getPackageDescription(report, Verification(self.path, None, "VKSC", None, None))
		failures = [str(m) for m in report.messages if m.type == ReportMessage.TYPE_FAIL]
		return package, failures

	def test_fractions_share_one_cfg (self):
		self.writeFile("vksc.cfg")
		for index in range(8):
			self.writeLog(index, 8, "vksc.cfg")
		package, failures = self.describe()
		self.assertEqual(failures, [])
		self.assertEqual(package.otherItems, [])

	def test_unreferenced_cfg_stays_unknown (self):
		self.writeFile("vksc.cfg")
		self.writeFile("other.cfg")
		for index in range(2):
			self.writeLog(index, 2, "vksc.cfg")
		package, failures = self.describe()
		self.assertEqual(failures, [])
		self.assertEqual(package.otherItems, ["other.cfg"])

	def test_missing_cfg_fails_every_log (self):
		for index in range(2):
			self.writeLog(index, 2, "vksc.cfg")
		package, failures = self.describe()
		self.assertEqual(len(failures), 2)
		for failure in failures:
			self.assertIn("subprocess cfg file specified but is not present in submission package", failure)

if __name__ == "__main__":
	unittest.main()
