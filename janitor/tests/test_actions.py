
import unittest

from janitor import actions


class TestActions(unittest.TestCase):

    def test_action_construction(self):

        self.assertIsInstance(
            actions.factory('mark'),
            actions.Mark)

        self.assertIsInstance(
            actions.factory('stop'),
            actions.Stop)

        self.assertIsInstance(
            actions.factory('notify-owner'),
            actions.NotifyOwner)        

        self.assertIsInstance(
            actions.factory('terminate'),
            actions.Terminate)        

        

