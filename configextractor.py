import cli
import json
import tempfile
import os
from assemblyline.odm.models.tagging import Tagging
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT


class ConfigExtractor(ServiceBase):
    """ Runs parsers derived from MWCP, CAPE
    """

    def __init__(self, config=None):
        super(ConfigExtractor, self).__init__(config)
        self.file_parsers = None
        self.tag_parsers = None
        self.all_parsers = None

    def start(self):
        # ==================================================================
        # On Startup actions:
        self.log.info(f"start() from {self.service_attributes.name} service called")
        yara_externals = {f'al_{x.replace(".", "_")}': "" for x in Tagging.flat_fields().keys()}
        file_parsers, tag_parsers = cli.compile(yara_externals)
        self.all_parsers = cli.validate_parser_config()
        self.file_parsers = file_parsers
        self.tag_parsers = tag_parsers

    def sectionBuilder(self, field_dict, result, parser, parsertype="MWCP"):
        # TODO add MWCP / CAPE field configuration
        # json_section= ResultSection("JSON Section", body_format=BODY_FORMAT.JSON, body=json.dumps(field_dict))
        # result.add_section(json_section)

        parser_section = ResultSection(f"{parsertype} : {parser}")
        fields_liststrings = {"address": "network.dynamic.uri", "c2_url": "network.dynamic.uri",
                              "c2_address": "network.dynamic.uri", "registrypath": "dynamic.registry_key",
                              "servicename": "", "filepath": "file.path", "missionid": "", "version": "",
                              "injectionprocess": "", "mutex": "", "directory": "", "servicedisplayname": "",
                              "servicedescription": "", "key": "", "password": ""}
        fields_dictstrings = {"other": ""}
        fields_liststringtuples = {"port": "network.dynamic.port"}
        for field, tag in fields_liststrings.items():
            if field in field_dict:
                generic_section = ResultSection(f" {field.capitalize()}  ")
                if field_dict[field]:  # if value is not empty raise signature
                    generic_section.set_heuristic(1)
                for line in field_dict[field]:
                    generic_section.add_line(f"{line}")

                if tag:
                    for x in field_dict[field]:
                        generic_section.add_tag(tag, x)
                parser_section.add_subsection(generic_section)

        for field, tag in fields_dictstrings.items():
            if field in field_dict:
                other_section = ResultSection(f"Other metadata found ")
                for k, v in field_dict['other'].items():
                    other_section.add_line(k)
                    other_section.add_line(v)
                parser_section.add_subsection(other_section)

        for field, tag in fields_liststringtuples.items():
            if field in field_dict:
                generic_section = ResultSection(f"{field.capitalize()} Section ")
                generic_section.add_lines(field_dict[field])
                if tag:
                    for x in field_dict[field]:
                        generic_section.add_tag(tag, x)
                parser_section.add_subsection(generic_section)

        result.add_section(parser_section)

    def execute(self, request):
        # ==================================================================
        # Execute a request:
        result = Result()
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
        example_fields = cli.run(parsers, request.file_path)
        for parser, field_dict in example_fields.items():
            self.sectionBuilder(field_dict, result, parser)
        fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
        with os.fdopen(fd, "w") as myfile:
            myfile.write(json.dumps(example_fields))
        request.add_supplementary(temp_path, "output.json", "This is MWCP output as a JSON file")

        request.result = result
