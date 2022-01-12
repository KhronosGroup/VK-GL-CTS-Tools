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
import sys
import argparse

from package import *
from report import *
from utils import *
from common import *

def parseArgs ():
	parser = argparse.ArgumentParser(description = "Generate verification report",
									 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument("package",
						help="Path to the package file (tgz)")
	parser.add_argument("-d",
						"--untar-dir",
						dest="untarDir",
						default=tempfile.mkdtemp(),
						help="Directory to untar the package")
	parser.add_argument("-v",
						"--verbose",
						dest="verbose",
						action="store_true",
						default=False,
						help="Print messages as it goes")
	parser.add_argument("-o",
						"--output",
						dest="output",
						default=None,
						help="Output file (if any)")
	parser.add_argument("-s",
						"--source",
						dest="source",
						default=None,
						help="VK-GL-CTS clone. If not supplied the script will attempt to clone.")
	parser.add_argument("-k",
						"--khronos",
						dest="khronos",
						action="store_true",
						default=False,
						help="Package name starts with the submission id. Required for submissions uploaded to Khronos.")
	return parser.parse_args()

if __name__ == "__main__":
	args			= parseArgs()
	ctsPath			= validateSource(args.source)
	report			= Report(args.verbose, args.output)

	packageFile		= os.path.normpath(sys.argv[1])
	packagePath		= args.untarDir
	packageFileBN	= os.path.basename(packageFile)

	idx				= -1
	submissionId	= None
	if args.khronos == True:
		try:
			idx = packageFileBN.index('-')
		except ValueError:
			report.failure("Submission id should be followed by a dash.")
		else:
			submissionId = packageFileBN[0 : idx]

	report.reportTitle(submissionId)
	report.reportSubTitle("Preliminary steps")

	res = untarPackage(report, packageFile, packagePath)
	if res == True:
		releaseTag = findReleaseTag(report, packagePath)

		if releaseTag != None:
			submissionType	= packageFileBN[idx + 1:].split("_")[0]
			m				= re.search(r'\d', submissionType)
			if m:
				idx				= m.start()
				apiType			= submissionType[:idx]
				apiVersion		= submissionType[idx:idx + 1] + "." + submissionType[idx + 1:]
			else:
				apiType = "Invalid"

			if apiType not in API_TYPE_DICT:
				report.failure("Incorrect package name: %s. The file should be named as \<API\>\<API version\>_\<Adopter\>_\<Info\>.tgz. See the README for more info." % packageFileBN)
			else:
				apiName		= API_TYPE_DICT[apiType] + ' ' + apiVersion

				verification = Verification(packagePath, ctsPath, apiType, apiVersion, releaseTag)
				if isSubmissionSupported(apiType):
					report.message("Started verification for %s" % apiName, packageFileBN)
					verify(report, verification)
				else:
					report.warning("Not supported type of submission: %s" % apiName, packageFileBN)

	report.generate()
