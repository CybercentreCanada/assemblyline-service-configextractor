import ast
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
    'c2_url': 'network.dynamic.uri',
    'credential': None,
    'directory': 'file.path',
    'email_address': None,
    'event': None,
    'filename': 'file.path',
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
    'ssl_cert_sha1': None,
    'url': 'network.dynamic.uri',
    'urlpath': None,
    'useragent': None,
    'username': 'file.string.extracted',
    'version': 'file.pe.versions.description'
}


class ConfigExtractor(ServiceBase):
    def __init__(self, config=None):
        super(ConfigExtractor, self).__init__(config)
        self.file_parsers = {}
        self.tag_parsers = None
        self.parser_classification = []  # default should be the classification set for the service.
        self.mwcp_report = None

    def start(self):
        yara_externals = {f'al_{x.replace(".", "_")}': "" for x in Tagging.flat_fields().keys()}
        yara_externals.update(
            {
                "al_file_rule_yara":""
            }
        )
        file_parsers, tag_parsers = cli.compile(yara_externals)
        self.log.info(f"loaded {list(file_parsers.keys())}")
        cli.validate_parser_config()
        self.file_parsers = file_parsers
        self.tag_parsers = tag_parsers

    def execute(self, request):
        self.mwcp_report = cli.register()
        result = Result()
        # Run Ratdecoders
        output = cli.run_ratdecoders(request.file_path, self.mwcp_report)
        if type(output) is str:
            self.log.info(output)
            output = ""
        if type(output) is dict:
            self.log.info(output)
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
        cli.run_mwcfg(request.file_path, self.mwcp_report)
        parsers = cli.deduplicate(self.file_parsers, self.tag_parsers, request.file_path, newtags)
        output_fields, _ = cli.run(parsers, request.file_path)


        for parser, field_dict in output_fields.items():
            self.section_builder(parser, field_dict, result)
            if "outputfile" in field_dict:
                # outputfile value is a list of lists containing filename, description and md5 has of additional
                # outputfiles
                outputfiles = field_dict['outputfile']
                for output_list in outputfiles:
                    output_filename = output_list[0]
                    output_description = output_list[1]
                    output_md5 = output_list[2]
                    output_fullpath = os.path.join(os.getcwd(), output_md5[:5] + '_' + output_filename)
                    request.add_supplementary(output_fullpath, output_filename, output_description)
        fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
        if output or output_fields:
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
        if parsertype == "RATDecoder":
            malware_name = parser
        if parsertype == "MWCP":
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
                    break
        parser_section = ResultSection(f"{parsertype} : {parser}")

        parser_section = classification_checker(parser_section, parser, self.file_parsers)
        if len(field_dict) > 0:  # if any decoder output exists raise heuristic
            parser_section.set_body(json.dumps(json_body), body_format=BODY_FORMAT.KEY_VALUE)
            parser_section.set_heuristic(HEURISTICS_MAP.get(category, 1), attack_id=mitre_att)
            parser_section.add_tag("source", f"{parsertype}.{parser}")

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
    for mwcp_field, mwcp_field_data in fields.items():
        if mwcp_field in FIELD_TAG_MAP and mwcp_field_data != ['-']:
            tag = FIELD_TAG_MAP[mwcp_field]
            table_body = []
            table_section = ResultSection(f"Extracted {mwcp_field.capitalize()}")

            # Make sure data isn't a string representation of a list
            for index, data in enumerate(mwcp_field_data):
                if isinstance(data, str) and all(symbol in data for symbol in ['[',']']):
                    mwcp_field_data.remove(data)
                    for x in ast.literal_eval(data):
                        mwcp_field_data.append(x)

            if tag:
                # Was a URL/URI tagged?
                if 'uri' in tag:
                    table_section.set_heuristic(3)

                for x in mwcp_field_data:
                    table_section.add_tag(tag, x)
                # Tag everything that we can
            # Add data to section body
            for line in mwcp_field_data:
                if type(line) is str:
                    table_body.append({mwcp_field: line})
                elif type(line) is list:
                    for item in line:
                        table_body.append({mwcp_field: item})
            table_section.set_body(body_format=BODY_FORMAT.TABLE, body=json.dumps(table_body))

            parent_section.add_subsection(table_section)
