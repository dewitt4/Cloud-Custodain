@filters.register('instance-attribute')
class InstanceAttribute(ValueFilter):
    """EC2 Instance Value FIlter on a given instance attribute.

    Filters EC2 Instances with the given instance attribute

    :Example:

    .. code-block:: yaml

        policies:
          - name: ec2-disabled-termination-protection
            resource: ec2
            filters:
              - type: instance-attribute
                key: termination-protection
                value: true
    """

    schema = type_schema(
        'instance-attribute',
        rinherit=ValueFilter.schema, **{
            'attribute-name':  {'type': 'string'}
        })

    def get_permissions(self):
        return ('ecc2:DescribeInstanceAttribute,)

    def process(self, resources, event=None):
        attribute_mapping = self.get_instance_attribute_mapping(resources)
        return [resource for resource in resources if self.matches_store(resource, attribute_mapping)]

    def matches_store(self, resource, mapping):
        stored = mapping[resource]
        return self.match(stored)

    def get_instance_attribute_mapping(self, resources):
        instance_value_map = {}
        attribute = self.data.get('key')
        client = utils.local_session(
            self.manager.session_factory).client('ec2')

        for resource in resources:
            fetched_attribute = self.retry(
                client.describe_instance_attribute,
                Attribute=attribute,
                InstanceId=resource['InstanceId'])
            instance_value_map[resource] = fetched_attribute
        return instance_value_map
