import hashlib
import json
import os
import sys
import tempfile
from base64 import b64encode
from typing import Any

import regex
from assemblyline.common import attack_map, forge
from assemblyline.odm.base import DOMAIN_ONLY_REGEX, FULL_URI, IP_ONLY_REGEX
from assemblyline.odm.models.ontology.results import MalwareConfig
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import (
    BODY_FORMAT,
    Heuristic,
    Result,
    ResultSection,
    ResultTableSection,
    TableRow,
)
from configextractor.main import ConfigExtractor as CX
from configextractor_.maco_tags import (
    extract_connection_tags,
    extract_DNS_tags,
    extract_FTP_tags,
    extract_HTTP_tags,
    extract_proxy_tags,
    extract_SMTP_tags,
    extract_SSH_tags,
)
from maco.model import ConnUsageEnum, ExtractorModel

cl_engine = forge.get_classification()

CONNECTION_USAGE = [k.name for k in ConnUsageEnum]


class Base64TruncatedEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            ret = b64encode(o).decode()
            if len(ret) > 1000:
                ret = ret[:1000] + '...'
            return ret
        return json.JSONEncoder.default(self, o)


class Base64Encoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return b64encode(o).decode()
        return json.JSONEncoder.default(self, o)


class ConfigExtractor(ServiceBase):
    def __init__(self, config=None):
        super(ConfigExtractor, self).__init__(config)
        self.cx = None
        self.source_map = None

    # Generate the rules_hash and init rules_list based on the raw files in the rules_directory from updater
    def _gen_rules_hash(self) -> str:
        self.rules_list = []
        for obj in os.listdir(self.rules_directory):
            obj_path = os.path.join(self.rules_directory, obj)
            if os.path.isdir(obj_path) and 'python_packages' not in obj_path:
                self.rules_list.append(obj_path)
        all_sha256s = [f for f in self.rules_list]

        if len(all_sha256s) == 1:
            return all_sha256s[0][:7]

        return hashlib.sha256(
            " ".join(sorted(all_sha256s)).encode("utf-8")
        ).hexdigest()[:7]

    def _clear_rules(self) -> None:
        for dir in self.rules_list:
            # Cleanup old modules
            for parser_module in [module for module in sys.modules.keys() if module.startswith(os.path.split(dir)[1])]:
                sys.modules.pop(parser_module)

    def _load_rules(self) -> None:
        if self.rules_list:
            self.log.debug(self.rules_list)
            blocklist = []
            blocklist_location = os.path.join(self.rules_directory, "blocked_parsers")
            self.source_map = json.loads(
                open(os.path.join(self.rules_directory, "source_mapping.json")).read()
            )
            python_packages_dir = os.path.join(self.rules_directory, "python_packages")
            if python_packages_dir not in sys.path:
                sys.path.append(python_packages_dir)

            if os.path.exists(blocklist_location):
                for line in open(blocklist_location, "r").read().splitlines():
                    _, source, _, parser_name = line.split("_", 3)
                    blocklist.append(rf".*{parser_name}$")
            self.log.info(
                f"Blocking the following parsers matching these patterns: {blocklist}"
            )
            self.cx = CX(
                parsers_dirs=self.rules_list,
                logger=self.log,
                parser_blocklist=blocklist,
            )

        if not self.cx:
            raise Exception(
                "Unable to start ConfigExtractor because can't find directory containing parsers"
            )

        if not self.cx.parsers:
            raise Exception(
                f"Unable to start ConfigExtractor because can't find parsers in given directory: {self.rules_directory}"
            )

    # Temporary tagging method until CAPE is switched over to MACO modelling
    def tag_output(self, output: Any, tags: dict = {}):
        def tag_string(value):
            if regex.search(IP_ONLY_REGEX, value):
                tags.setdefault("network.static.ip", []).append(value)
            elif regex.search(DOMAIN_ONLY_REGEX, value):
                tags.setdefault("network.static.domain", []).append(value)
            elif regex.search(FULL_URI, value):
                tags.setdefault("network.static.uri", []).append(value)

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

    def network_ioc_section(self, config, request, extra_tags) -> ResultSection:
        network_section = ResultSection("Network IOCs")

        network_fields = {
            "ftp": (ExtractorModel.FTP, extract_FTP_tags),
            "smtp": (ExtractorModel.SMTP, extract_SMTP_tags),
            "http": (ExtractorModel.Http, extract_HTTP_tags),
            "ssh": (ExtractorModel.SSH, extract_SSH_tags),
            "proxy": (ExtractorModel.Proxy, extract_proxy_tags),
            "dns": (ExtractorModel.DNS, extract_DNS_tags),
            "tcp": (ExtractorModel.Connection, extract_connection_tags),
            "udp": (ExtractorModel.Connection, extract_connection_tags),
        }
        request.temp_submission_data.setdefault('url_headers', {})
        for field, model_tuple in network_fields.items():
            sorted_network_config = {}
            for network_config in config.pop(field, []):
                if field == 'http' and network_config.get('uri'):
                    headers = network_config.get('headers', {})
                    if network_config.get('user_agent'):
                        headers.update({'User-Agent': network_config['user_agent']})
                    request.temp_submission_data['url_headers'].update({network_config['uri']: headers})
                sorted_network_config.setdefault(network_config.get("usage", "other"), []).append(network_config)

            if sorted_network_config:
                connection_section = ResultSection(field.upper())
                for usage, connections in sorted_network_config.items():
                    model, tag_extractor = model_tuple
                    tags = tag_extractor(connections)
                    heuristic = Heuristic(2, signature=usage)
                    auto_collapse = False
                    if usage in ["decoy", "other"]:
                        # Display connections, but don't tag/score
                        tags, heuristic, auto_collapse = {}, None, True

                    # Propagate extra tags to section
                    tags.update(extra_tags)
                    table_section = ResultTableSection(
                        title_text=f"Usage: {usage.upper()} x{len(connections)}",
                        heuristic=heuristic,
                        tags=tags,
                        auto_collapse=auto_collapse
                    )
                    for c in connections:
                        c.pop("usage", None)
                        table_section.add_row(TableRow(**model(**c).dict()))

                    if table_section.body:
                        connection_section.add_subsection(table_section)

                if connection_section.subsections:
                    network_section.add_subsection(connection_section)

        if network_section.subsections:
            return network_section

    def attach_ontology(self, config: dict):
        def strip_null(d: dict):
            clean_config = {}
            for k, v in d.items():
                if v:
                    if isinstance(v, dict):
                        clean_config[k] = strip_null(v)
                    elif isinstance(v, list) and isinstance(v[0], dict):
                        clean_config[k] = [strip_null(vi) for vi in v]
                    else:
                        clean_config[k] = v
            return clean_config
        self.ontology.add_result_part(MalwareConfig, strip_null(config))

    def execute(self, request):
        result = Result()
        config_result = self.cx.run_parsers(request.file_path)
        if not config_result:
            request.result = result
            return

        a = tempfile.NamedTemporaryFile(delete=False)
        a.write(json.dumps(config_result, cls=Base64Encoder).encode())
        a.seek(0)
        request.add_supplementary(
            a.name,
            f"{request.sha256}_malware_config.json",
            "Raw output from configextractor-py",
        )
        for parser_framework, parser_results in config_result.items():
            for parser_name, parser_output in parser_results.items():
                # Get AL-specific details about the parser
                id = f"{parser_framework}_{parser_name}"
                classification = self.source_map[id]["classification"]
                source_name = self.source_map[id]["source_name"]
                if not parser_output.get('config'):
                    # No configuration therefore skip
                    continue

                config = parser_output.pop("config")

                # Correct revoked ATT&CK IDs
                for i, v in enumerate(config.get('attack', [])):
                    config['attack'][i] = attack_map.revoke_map.get(v, v)

                # Account for the possibility of 'family' field to be a string (Output of MACO <= 1.0.2)
                if isinstance(config['family'], str):
                    config['family'] = [config['family']]

                # Include extractor's name for ontology output only
                config['config_extractor'] = config.get('config_extractor', f"{source_name}.{parser_name}")
                self.attach_ontology(config)
                config.pop('config_extractor')

                if not config.get('family'):
                    # Family isn't included in the output which is required!
                    # Move onto next result, but log which parser needs correcting.
                    self.log.warning(f"[{parser_framework}] {parser_name} is missing 'family' in it's output "
                                     "which is mandatory to the MaCo spec. Moving onto next result...")
                    continue

                parser_output["family"] = config.pop("family")
                parser_output["Framework"] = parser_framework

                tags = {
                    "file.rule.configextractor": [f"{source_name}.{parser_name}"],
                    "attribution.family": [f for f in parser_output["family"]],
                    "attribution.implant": [f for f in parser_output["family"]],
                }
                attack_ids = config.pop("attack", [])
                for field in ["category", "version"]:
                    if config.get(field):
                        parser_output[field] = config.pop(field)

                if config.get("password"):
                    password = config.pop("password", [])
                    parser_output["password"] = password
                    tags.update({"info.password": password})

                if config.get("campaign_id"):
                    campaign_id = config.pop("campaign_id", [])
                    parser_output["Campaign ID"] = campaign_id
                    tags.update({"attribution.campaign": campaign_id})

                parser_section = ResultSection(
                    title_text=parser_name,
                    body=json.dumps(parser_output),
                    parent=result,
                    body_format=BODY_FORMAT.KEY_VALUE,
                    tags=tags,
                    heuristic=Heuristic(1, attack_ids=attack_ids),
                    classification=classification,
                )
                extra_tags = {"file.rule.configextractor": [f"{source_name}.{parser_name}"]}
                network_section = self.network_ioc_section(config, request, extra_tags=extra_tags)
                if network_section:
                    parser_section.add_subsection(network_section)

                for binary in config.get('binaries', []):
                    # Append binary data to submission for analysis
                    datatype = binary.get('datatype', 'other')
                    data = binary.get('data')
                    if datatype in ['other', 'payload'] and data:
                        if isinstance(data, str):
                            data = data.encode()
                        sha256 = hashlib.sha256(data).hexdigest()
                        a = tempfile.NamedTemporaryFile(delete=False)
                        a.write(data)
                        a.close()
                        request.add_extracted(
                            a.name,
                            f"binary_{datatype}_{sha256}",
                            "Extracted binary file",
                        )

                if config:
                    other_tags = {}
                    self.tag_output(config, other_tags)
                    ResultSection(
                        "Other data",
                        body=json.dumps(config, cls=Base64TruncatedEncoder),
                        body_format=BODY_FORMAT.JSON,
                        parent=parser_section,
                        tags=other_tags
                    )

        request.result = result
