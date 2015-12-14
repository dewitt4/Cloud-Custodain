"""
Get tag key population count from a maid resources.json file
"""

import argparse
from collections import Counter
import json
import os


def main():
    p = argparse.ArgumentParser()
    p.add_argument('-f', '--resources', required=True)
    p.add_argument('-n', '--min-count', type=int, default=0)
    
    options = p.parse_args()

    resource_path = os.path.expandvars(os.path.expanduser(options.resources))

    if not os.path.exists(resource_path):
        raise ValueError("Invalid file path %s" % resource_path)

    with open(resource_path) as fh:
        resources = json.load(fh)

    counter = Counter()
    
    for r in resources:
        counter.update(
            [t['Key'] for t in r.get('Tags', []) if not t['Key'].startswith('aws:')])
        
    tags = [(v, k) for k, v in sorted(
        [(v, k) for k, v in counter.items() if v > options.min_count],
        reverse=True)]
    for k, v in tags:
        print k, v

    
if __name__ == '__main__':
    main()
