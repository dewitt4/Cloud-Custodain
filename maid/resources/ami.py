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
import logging

from maid.actions import ActionRegistry, BaseAction
from maid.filters import FilterRegistry, AgeFilter

from maid.manager import ResourceManager, resources
from maid.utils import local_session


log = logging.getLogger('maid.ami')


filters = FilterRegistry('ami.filters')
actions = ActionRegistry('ami.actions')


@resources.register('ami')
class AMI(ResourceManager):

    # FIXME: Rename all 'data' variables to something meaningful
    def __init__(self, ctx, data):
        super(AMI, self).__init__(ctx, data)
        # FIXME: Move these to ResourceManager.__init__?
        self.filters = filters.parse(
            self.data.get('filters', []), self)
        self.actions = actions.parse(
            self.data.get('actions', []), self) 

    def resources(self):
        c = self.session_factory().client('ec2')
        query = self.resource_query()  # FIXME: Not used
        self.log.info("Querying images")
        images = c.describe_images(Owners=['self'], Filters=query)['Images']
        return self.filter_resources(images)


@actions.register('deregister')
class Deregister(BaseAction):

    def process(self, images):
        with self.executor_factory(max_workers=10) as w:
            list(w.map(self.process_image, images))

    def process_image(self, image):
        client = local_session(self.manager.session_factory).client('ec2')
        client.deregister_image(ImageId=image['ImageId'])

        
@filters.register('image-age')        
class ImageAgeFilter(AgeFilter):

    date_attribute = "CreationDate"
