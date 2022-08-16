from collections import defaultdict
from typing import Any

from assemblyline.common import forge
from assemblyline.odm.base import IP_ONLY_REGEX, FULL_URI, DOMAIN_ONLY_REGEX
from assemblyline.odm.models.tagging import Tagging
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, ResultTableSection, BODY_FORMAT, TableRow, Heuristic

import json
import hashlib
import os
import regex
import tempfile

from configextractor.main import ConfigExtractor as CX
from maco.model import ExtractorModel, ConnUsageEnum

cl_engine = forge.get_classification()

CONNECTION_USAGE = [k.name for k in ConnUsageEnum]


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

    def network_ioc_section(self, config) -> ResultSection:
        network_section = ResultSection("Network IOCs")

        network_fields = {
            'ftp': ExtractorModel.FTP,
            'smtp': ExtractorModel.SMTP,
            'http': ExtractorModel.Http,
            'ssh': ExtractorModel.SSH,
            'proxy': ExtractorModel.Proxy,
            'dns': ExtractorModel.DNS,
            'tcp': ExtractorModel.Connection,
            'udp': ExtractorModel.Connection
        }
        for field, model in network_fields.items():
            sorted_network_config = {}
            for network_config in config.get(field, []):
                sorted_network_config.setdefault(network_config.get('usage', 'other'), []).append(network_config)

            if sorted_network_config:
                connection_section = ResultSection(field.upper(), parent=network_section)
                for usage, connections in sorted_network_config.items():
                    tags = list()
                    self.tag_output(connections, tags)
                    table_section = ResultTableSection(title_text=f"Usage: {usage.upper()} x{len(connections)}", parent=connection_section, heuristic=Heuristic(2, signature=usage), tags=tags)
                    [table_section.add_row(TableRow(**model(**c).dict())) for c in connections]

        if network_section.subsections:
            return network_section

    def execute(self, request):
        result = Result()
        config_result = self.cx.run_parsers(request.file_path)
        if not config_result:
            request.result = result
            return

        a = tempfile.NamedTemporaryFile(delete=False)
        a.write(json.dumps(config_result).encode())
        a.seek(0)
        request.add_supplementary(a.name, f"{request.sha256}_malware_config.json", "Raw output from configextractor-py")
        for parser_framework, parser_results in config_result.items():
            framework_section = ResultSection(parser_framework, parent=result, auto_collapse=True)
            for parser_name, parser_output in parser_results.items():
                config = parser_output.pop('config')
                parser_output['family'] = config.pop('family')
                parser_section = ResultSection(title_text=parser_name, body=json.dumps(parser_output), parent=framework_section, body_format=BODY_FORMAT.KEY_VALUE)
                network_section = self.network_ioc_section(config)
                if network_section:
                    parser_section.add_subsection(network_section)


        request.result = result
