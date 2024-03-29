"""
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

 Copyright (C) CERN 2013-2021
"""

import glob
import unittest


def create_test_suite():
    """ create the suite with all the tests """
    test_file_strings = glob.glob('test/*test.py')
    module_strings = ['test.' + string[5:-3]
                      for string in test_file_strings]
    suites = [unittest.defaultTestLoader.loadTestsFromName(name)
              for name in module_strings]
    test_suite = unittest.TestSuite(suites)
    return test_suite
