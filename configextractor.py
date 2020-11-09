import cli
import json
import tempfile
import os

from assemblyline.common import forge
from assemblyline.odm.models.tagging import Tagging
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

cl_engine = forge.get_classification()

HEURISTICS_MAP = {"malware": 1, "safe": 2}
# This dict contains fields that we care about, and the corresponding tag if they exist
FIELD_TAG_MAP = {
    'address': 'network.dynamic.uri',
    'c2_address': 'network.dynamic.uri',
    'c2_socketaddress': None,
    'c2_url': 'network.dynamic.uri',
    'credential': None,
    'directory': None,
    'email_address': None,
    'event': None,
    'filename': None,
    'filepath': 'file.path',
    'ftp': None,
    'guid': None,
    'injectionprocess': None,
    'interval': None,
    'key': None,
    'listenport': None,
    'missionid': None,
    'mutex': 'dynamic.mutex',
    'outputfile': None,
    'password': 'file.string.extracted',
    'pipe': None,
    'proxy': None,
    'proxy_address': None,
    'proxy_socketaddress': None,
    'registrydata': None,
    'registrypath': 'dynamic.registry_key',
    'registrypathdata': None,
    'rsa_private_key': None,
    'rsa_public_key': None,
    'service': None,
    'servicedescription': None,
    'servicedisplayname': None,
    'servicedll': None,
    'serviceimage': None,
    'servicename': None,
    'socketaddress': None,
    'ssl_cert_sha1': None,
    'url': None,
    'urlpath': None,
    'useragent': None,
    'username': 'file.string.extracted',
    'version': 'file.pe.versions.description'
}


class ConfigExtractor(ServiceBase):
    def __init__(self, config=None):
        super(ConfigExtractor, self).__init__(config)
        self.file_parsers = None
        self.tag_parsers = None
        self.all_parsers = None
        self.parser_classification = []  # default should be the classification set for the service.
        self.mwcp_reporter = cli.register()

    def start(self):
        yara_externals = {f'al_{x.replace(".", "_")}': "" for x in Tagging.flat_fields().keys()}
        file_parsers, tag_parsers = cli.compile(yara_externals)
        self.log.info(f"loaded {file_parsers}")
        self.all_parsers = cli.validate_parser_config()
        self.file_parsers = file_parsers
        self.tag_parsers = tag_parsers

    def execute(self, request):
        result = Result()
        # clear metadata from previous submision since ratdecoder run doesn't clear metadata
        self.mwcp_reporter._Reporter__reset()
        # Run Ratdecoders
        output = cli.run_ratdecoders(request.file_path, self.mwcp_reporter)
        if type(output) in [dict, str]:
            self.log.info(output)
        if type(output) is dict:
            for parser, fields in output.items():
                self.section_builder(parser, fields, result, "RATDecoder")

        tags = {f"al_{k.replace('.', '_')}": i for k, i in request.task.tags.items()}
        newtags = {}
        # yara externals must be dicts w key value pairs being strings
        for k, v in tags.items():
            key = f"al_{k.replace('.', '_')}"
            for i in range(len(v)):
                if not isinstance(v[i], str):
                    v[i] = str(v[i])
            value = " | ".join(v)
            newtags[key] = value
        # get matches for both, dedup then run
        parsers = cli.deduplicate(self.file_parsers, self.tag_parsers, request.file_path, newtags)
        output_fields = cli.run(parsers, request.file_path, self.mwcp_reporter)

        for parser, field_dict in output_fields.items():
            self.section_builder(parser, field_dict, result)
        fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
        with os.fdopen(fd, "w") as myfile:
            myfile.write(json.dumps(output))
            myfile.write(json.dumps(output_fields))
        request.add_supplementary(temp_path, "output.json", "This is MWCP output as a JSON file")

        request.result = result

    def section_builder(self, parser, field_dict, result, parsertype="MWCP"):
        json_body = {}
        malware_name = ''
        malware_types = []
        mitre_group = ''
        mitre_att = ''
        category = 'malware'
        # get malware names from parser objects
        for name, obj in self.file_parsers.items():
            if parser in obj.parser_list:
                malware_name = obj.malware
                malware_types = obj.malware_types
                mitre_att = obj.mitre_att
                mitre_group = obj.mitre_group
                category = obj.category
                for item in ['classification', 'mitre_group', 'mitre_att',
                             'malware', 'malware_types', 'category']:
                    val = getattr(obj, item, None)
                    if val:
                        json_body[item] = val
        parser_section = ResultSection(f"{parsertype} : {parser}")

        parser_section = classification_checker(parser_section, parser, self.file_parsers)
        if len(field_dict) > 0:  # if any decoder output exists raise heuristic
            parser_section.set_body(json.dumps(json_body), body_format=BODY_FORMAT.KEY_VALUE)
            parser_section.set_heuristic(HEURISTICS_MAP.get(category, 1), attack_id=mitre_att)
            parser_section.add_tag("source", parsertype)
            if malware_name:
                parser_section.add_tag('attribution.implant', malware_name.upper())
            if mitre_group:
                parser_section.add_tag('attribution.actor', mitre_group.upper())
            for malware_type in malware_types:
                parser_section.add_tag('attribution.family', malware_type.upper())
        # Create subsections and attach them to the main parser_section
        subsection_builder(parser_section, field_dict)

        other_key = "other"
        if other_key in field_dict:
            other_content = field_dict[other_key]
            other_section = ResultSection(f"Other metadata found", body_format=BODY_FORMAT.KEY_VALUE,
                                          body=json.dumps(other_content))
            parser_section.add_subsection(other_section)

        for field in field_dict:
            if field != other_key and field not in FIELD_TAG_MAP:
                self.log.debug(f"{field} does not exist in FIELD_TAG_MAP")
        result.add_section(parser_section)


def classification_checker(res_section, parser_name, file_parsers):
    for name, parser_obj in file_parsers.items():
        if name == parser_name:
            res_section.classification = cl_engine.normalize_classification(parser_obj.classification)
    return res_section


def subsection_builder(parent_section: ResultSection = None, fields: dict = {}):
    for field, tag in FIELD_TAG_MAP.items():
        if field in fields:
            generic_section = ResultSection(f"Extracted {field.capitalize()}")
            field_data = fields[field]
            if tag:
                for x in field_data:
                    generic_section.add_tag(tag, x)
                # Tag it all and then don't print, since that duplicates info
            else:
                # Add data to section body if no tag exists
                for line in field_data:
                    if type(line) is str:
                        generic_section.add_line(f"{line}")
                    elif type(line) is list:
                        generic_section.add_lines(line)
            parent_section.add_subsection(generic_section)
