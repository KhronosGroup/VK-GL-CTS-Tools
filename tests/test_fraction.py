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

# Tests for --deqp-fraction handling: log name parsing, command line
# checks and the per-log check in getPackageDescription.
# Run from the repository root with: python3 -m unittest discover -s tests

import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from package import FRACTION_REGEX, getPackageDescription, parseCmds
from report import Report, ReportMessage
from utils import CommandLineParserVk, Verification

MANDATORY_ARGS = "--deqp-caselist-file=vk-default.txt --deqp-log-images=disable --deqp-log-shader-sources=disable"

def fractionArgs (index, count):
	return "%s --deqp-fraction=%d,%d --deqp-fraction-mandatory-caselist-file=vk-fraction-mandatory-tests.txt" % (MANDATORY_ARGS, index, count)

class FractionRegexTest(unittest.TestCase):
	def test_parses_whole_index_and_count (self):
		cases = [
			("TestResults-0-of-16.qpa",						(0, 16)),
			("TestResults-9-of-16.qpa",						(9, 16)),
			("TestResults-12-of-16.qpa",					(12, 16)),
			("TestResults-15-of-16.qpa",					(15, 16)),
			("Testresults-arm64-v8a-12-of-16.qpa",			(12, 16)),
			("12-of-16.qpa",								(12, 16)),
			("log_3-of-4.qpa",								(3, 4)),
		]
		reobj = re.compile(FRACTION_REGEX)
		for name, expected in cases:
			with self.subTest(name=name):
				m = reobj.match(name)
				self.assertIsNotNone(m)
				self.assertEqual((int(m.group(1)), int(m.group(2))), expected)

	def test_rejects_other_names (self):
		reobj = re.compile(FRACTION_REGEX)
		for name in ["TestResults.qpa", "TestResults-1-of-2.qpa.bak", "TestResults-1-of-2xqpa", "TestResults-of-2.qpa"]:
			with self.subTest(name=name):
				self.assertIsNone(reobj.match(name))

class FractionCommandLineTest(unittest.TestCase):
	def setUp (self):
		self.parser = CommandLineParserVk("VK")

	def test_valid_fractions (self):
		for index in range(16):
			with self.subTest(index=index):
				args = parseCmds(self.parser, fractionArgs(index, 16))
				self.assertEqual(args.deqp_fraction, [index, 16])

	def test_no_fraction_defaults_to_whole_run (self):
		self.assertEqual(parseCmds(self.parser, MANDATORY_ARGS).deqp_fraction, [0, 1])

	def test_invalid_fractions (self):
		for index, count in [(16, 16), (-1, 16), (0, 17), (0, 0)]:
			with self.subTest(fraction=(index, count)):
				with self.assertRaises(Exception):
					parseCmds(self.parser, fractionArgs(index, count))

	def test_fraction_needs_mandatory_caselist (self):
		with self.assertRaises(Exception):
			parseCmds(self.parser, MANDATORY_ARGS + " --deqp-fraction=1,16")

class FractionPackageTest(unittest.TestCase):
	# Fake submission package with one test log per fraction; each log holds
	# only the session info line that getPackageDescription reads.

	def setUp (self):
		self.tmp = tempfile.TemporaryDirectory()
		self.path = self.tmp.name

	def tearDown (self):
		self.tmp.cleanup()

	def writeLog (self, name, args):
		with open(os.path.join(self.path, name), "w") as f:
			f.write("#sessionInfo commandLineParameters \"%s\"\n" % args)

	def describe (self):
		report = Report(False, None)
		package = getPackageDescription(report, Verification(self.path, None, "VK", None, None))
		failures = [m for m in report.messages if m.type == ReportMessage.TYPE_FAIL]
		return package, failures

	def test_sixteen_fractions_pass (self):
		for index in range(16):
			self.writeLog("TestResults-arm64-v8a-%d-of-16.qpa" % index, fractionArgs(index, 16))
		package, failures = self.describe()
		self.assertEqual([str(m) for m in failures], [])
		self.assertEqual(len(package.testLogs), 1)
		self.assertEqual(len(list(package.testLogs.values())[0]), 16)

	def test_fraction_mismatch_fails (self):
		self.writeLog("TestResults-12-of-16.qpa", fractionArgs(11, 16))
		package, failures = self.describe()
		self.assertEqual(len(failures), 1)
		self.assertIn("doesn't match test log name 12-of-16", str(failures[0]))

	def test_log_without_fraction_in_fractional_package_fails (self):
		self.writeLog("TestResults-0-of-2.qpa", fractionArgs(0, 2))
		self.writeLog("TestResults.qpa", fractionArgs(1, 2))
		package, failures = self.describe()
		self.assertTrue(any("does not conform to --deqp-fraction" in str(m) for m in failures))

if __name__ == "__main__":
	unittest.main()
