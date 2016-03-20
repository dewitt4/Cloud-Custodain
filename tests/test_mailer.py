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


from maid.mailer import MessageDB


class MessageDBTest(unittest.TestCase):

    def xtest_add_batch_flush(self):
        db = MessageDB(":memory:")
        db.add('serious@example.com', 'abc')
        db.add('serious@example.com', 'def')
        db.add('someone@example.com', 'def')

        self.assertEqual([
            ['serious@example.com', ['abc', 'def']],
            ['someone@example.com', ['def']]
            ],
            db.batches())

        


    
