import unittest


from janitor.mailer import MessageDB


class MessageDBTest(unittest.TestCase):

    def test_add_batch_flush(self):
        db = MessageDB(":memory:")

        

    
