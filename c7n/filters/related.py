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
from __future__ import absolute_import, division, print_function, unicode_literals

import importlib

import jmespath

from .core import ValueFilter


class RelatedResourceFilter(ValueFilter):

    RelatedResource = None
    RelatedIdsExpression = None
    AnnotationKey = None
    FetchThreshold = 10

    def get_permissions(self):
        return self.get_resource_manager().get_permissions()

    def validate(self):
        name = self.__class__.__name__
        if self.RelatedIdsExpression is None:
            raise ValueError(
                "%s Filter requires resource expression" % name)
        # if self.AnnotationKey is None:
        #    raise ValueError(
        #        "%s Filter requires annotation key" % name)

        if self.RelatedResource is None:
            raise ValueError(
                "%s Filter requires resource manager spec" % name)
        return super(RelatedResourceFilter, self).validate()

    def get_related_ids(self, resources):
        return set(jmespath.search(
            "[].%s" % self.RelatedIdsExpression, resources))

    def get_related(self, resources):
        resource_manager = self.get_resource_manager()
        related_ids = self.get_related_ids(resources)
        model = resource_manager.get_model()
        if len(related_ids) < self.FetchThreshold:
            related = resource_manager.get_resources(list(related_ids))
        else:
            related = resource_manager.resources()
        return {r[model.id]: r for r in related
                if r[model.id] in related_ids}

    def get_resource_manager(self, with_filter=False):
        mod_path, class_name = self.RelatedResource.rsplit('.', 1)
        module = importlib.import_module(mod_path)
        manager_class = getattr(module, class_name)

        data = {}
        if self.data.get('filters') and with_filter:
            data['filters'] = self.data['filters']
        return manager_class(self.manager.ctx, data)

    def process_resource(self, resource, related):
        related_ids = self.get_related_ids([resource])
        model = self.manager.get_model()
        op = self.data.get('operator', 'or')
        items = []
        if self.data.get('match-resource') is True:
            self.data['value'] = self.get_resource_value(
                self.data['key'], resource)
        for rid in related_ids:
            robj = related.get(rid, None)
            if robj is None:
                self.log.warning(
                    "Resource %s:%s references non existant %s: %s",
                    model.type,
                    resource[model.id],
                    self.RelatedResource.rsplit('.', 1)[-1],
                    rid)
                continue
            items.append(robj)

        filtered = []
        # Now, we filter accordingly...

        related_manager = self.get_resource_manager(True)
        related_model = related_manager.get_model()
        if self.data.get('filters'):
            filtered = related_manager.filter_resources(items)
        else:
            filtered = filter(self.match, items)

        if self.AnnotationKey is not None:
            resource['c7n:%s' % self.AnnotationKey] = map(lambda r: r[related_model.id], filtered)
            resource['c7n:full:%s' % self.AnnotationKey] = filtered

        if op == 'or' and filtered:
            return True
        elif op == 'and' and len(filtered) == len(items):
            return True
        return False

    def process(self, resources, event=None):
        related = self.get_related(resources)
        return [r for r in resources if self.process_resource(r, related)]
