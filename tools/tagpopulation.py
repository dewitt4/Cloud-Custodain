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
