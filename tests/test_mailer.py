import unittest


from janitor.mailer import MessageDB


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

        


    
