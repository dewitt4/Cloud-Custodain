import csv
import json
import operator

from janitor import actions

def _serialize_json(instances, fh):
    json.dump(
        [{'instance-id': i.id,
          'tags': i.tags,
          'ami': i.image_id,
          'key': i.key_name,
          'created': i.launch_time,
          'type': i.instance_type} for i in instances],
        fh, indent=2)


def _serialize_csv(instances, fh):
    writer = csv.writer(fh)
    writer.writerow(
        ('name',
         'launch_time',
         'instance_type',
         'image_id',
         'key_name',
         'asv',
         'cmdbenv'))
    for i in instances:
        writer.writerow((
            i.tags.get('Name', "NA"),
            i.launch_time,
            i.instance_type,
            i.image_id,
            i.key_name,
            i.tags.get("ASV", "NA"),
            i.tags.get("CMDBEnvironment", "NA")                
        ))

        
def identify(options, policy):
    instances = sorted(
        policy.inventory, key=operator.attrgetter('launch_time'))
    with open(options.csv_file, 'w') as fh:
        if options.format == "json":
            _serialize_json(instances, fh)
        else:
            _serialize_csv(instances, fh)


def mark(options, policy):
    instances = list(policy.inventory)
    mark = actions.Mark(options, policy)
    mark.process(instances)


def run(options, policy):
    instances = list(policy.inventory)
    for a in policy.actions:
        a.process(instances)
