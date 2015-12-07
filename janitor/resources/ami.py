import logging

from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry, AgeFilter

from janitor.manager import ResourceManager, resources
from janitor.utils import local_session


log = logging.getLogger('maid.ami')

filters = FilterRegistry('ami.filters')
actions = ActionRegistry('ami.actions')


@resources.register('ami')
class AMI(ResourceManager):

    def __init__(self, ctx, data):
        super(AMI, self).__init__(ctx, data)
        self.filters = filters.parse(
            self.data.get('filters', []), self)
        self.actions = actions.parse(
            self.data.get('actions', []), self) 

    def resources(self):
        c = self.session_factory().client('ec2')
        query = self.resource_query()
        self.log.info("Querying images")
        images = c.describe_images(Owners=['self'])['Images']
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
