import unittest

from janitor.inventory import Inventory
from janitor.filters import filter

from janitor.tests.common import Instance, Client, Config


class TestInventory(unittest.TestCase):

    def test_inventory_filters(self):

        instances = [
            Instance({'id': 1,
                      'tags': {'ASV': '123',
                               'CMDBEnvironment': '123'}}),
            Instance({'id': 2,
                      'tags': {}}),
            Instance({'id': 3,
                      'tags': {'CMDBEnvironment': '123'}}),
            Instance({'id': 4,
                      'tags': {'ASV': '123'}})]

        client = Client(instances)        
        conf = Config({"cache_period": 0, 'cache': ''})
        filters = [
            filter({'filter': 'tag:ASV', 'state': 'absent'}),
            filter({'filter': 'tag:CMDBEnvironment', 'state': 'absent'})]
        i = Inventory(client, filters, conf)

        self.assertEqual(
            [x.id for x in list(i)],
            [x.id for x in instances[1:]])
                         
        
            
            




