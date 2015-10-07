
import unittest

from janitor import actions


class TestActions(unittest.TestCase):

    def test_action_construction(self):

        self.assertIsInstance(
            actions.factory('mark', None),
            actions.Mark)

        self.assertIsInstance(
            actions.factory('stop', None),
            actions.Stop)

        self.assertIsInstance(
            actions.factory('notify-owner', None),
            actions.NotifyOwner)        

        self.assertIsInstance(
            actions.factory('terminate', None),
            actions.Terminate)        

        

