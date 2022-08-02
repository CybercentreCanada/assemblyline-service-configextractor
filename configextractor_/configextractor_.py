from collections import defaultdict
from typing import Any

from assemblyline.common import forge
from assemblyline.odm.base import IP_ONLY_REGEX, FULL_URI, DOMAIN_ONLY_REGEX
from assemblyline.odm.models.tagging import Tagging
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

import json
import hashlib
import os
import regex

from configextractor.main import ConfigExtractor as CX


cl_engine = forge.get_classification()


class ConfigExtractor(ServiceBase):
    def __init__(self, config=None):
        super(ConfigExtractor, self).__init__(config)
        self.cx = None

    # Generate the rules_hash and init rules_list based on the raw files in the rules_directory from updater
    def _gen_rules_hash(self) -> str:
        self.rules_list = []
        for obj in os.listdir(self.rules_directory):
            obj_path = os.path.join(self.rules_directory, obj)
            if os.path.isdir(obj_path):
                self.rules_list.append(obj_path)
        all_sha256s = [f for f in self.rules_list]

        if len(all_sha256s) == 1:
            return all_sha256s[0][:7]

        return hashlib.sha256(' '.join(sorted(all_sha256s)).encode('utf-8')).hexdigest()[:7]

    def _load_rules(self) -> None:
        if self.rules_list:
            self.log.debug(self.rules_list)
            blocklist = []
            blocklist_location = os.path.join(self.rules_directory, 'blocked_parsers')
            if os.path.exists(blocklist_location):
                for line in open(blocklist_location, 'r').readlines():
                    _, source, _, parser_name = line.split('_', 3)
                    blocklist.append(rf".*{parser_name}$")
            self.log.info(f'Blocking the following parsers matching these patterns: {blocklist}')
            self.cx = CX(parsers_dirs=self.rules_list, logger=self.log, parser_blocklist=blocklist)

        if not self.cx:
            raise Exception("Unable to start ConfigExtractor because can't find directory containing parsers")

        if not self.cx.parsers:
            raise Exception(
                f"Unable to start ConfigExtractor because can't find parsers in given directory: {self.rules_directory}")

    # Temporary tagging method until CAPE is switched over to MACO modelling
    def tag_output(self, output: Any, tags: dict = {}):
        def tag_string(value):
            if regex.search(IP_ONLY_REGEX, value):
                tags['network.static.ip'].append(value)
            elif regex.search(DOMAIN_ONLY_REGEX, value):
                tags['network.static.domain'].append(value)
            elif regex.search(FULL_URI, value):
                tags['network.static.uri'].append(value)

        if isinstance(output, dict):
            # Iterate over valuse of dictionary
            for value in output.values():
                if isinstance(value, dict):
                    self.tag_output(value, tags)
                elif isinstance(value, list):
                    [self.tag_output(v, tags) for v in value]
                elif isinstance(value, str):
                    tag_string(value)

        elif isinstance(output, str):
            tag_string(output)

    def execute(self, request):
        result = Result()
        config_result = self.cx.run_parsers(request.file_path)
        tags = defaultdict(list)
        self.tag_output(config_result, tags)
        result.add_section(ResultSection('Output', body=json.dumps(config_result),
                                         body_format=BODY_FORMAT.JSON, tags=tags))
        request.result = result
