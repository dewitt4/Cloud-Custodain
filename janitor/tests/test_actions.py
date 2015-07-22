
import unittest

from janitor import actions


class TestActions(unittest.TestCase):

    def test_action_construction(self):

        self.assertIsInstance(
            actions.action('mark', None, None),
            actions.Mark)

        self.assertIsInstance(
            actions.action('stop', None, None),
            actions.Stop)

        self.assertIsInstance(
            actions.action('notify-owner', None, None),
            actions.NotifyOwner)        

        self.assertIsInstance(
            actions.action('terminate', None, None),
            actions.Terminate)        

        

