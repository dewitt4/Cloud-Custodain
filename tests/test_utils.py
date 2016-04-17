# Copyright 2016 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from c7n import utils


class UtilTest(unittest.TestCase):

    def test_chunks(self):
        self.assertEqual(
            list(utils.chunks(range(100), size=50)),
            [range(50), range(50, 100, 1)])
        self.assertEqual(
            list(utils.chunks(range(1), size=50)),
            [range(1)])
        self.assertEqual(
            list(utils.chunks(range(60), size=50)),
            [range(50), range(50, 60, 1)])
        
    def test_type_schema(self):
        self.assertEqual(
            utils.type_schema('tester'),
            {'type': 'object',
             'additionalProperties': False,
             'required': ['type'],
             'properties': {
                 'type': {'enum': ['tester']}}})
        
