import cli
import json
import tempfile
import os
from assemblyline.common import forge
from assemblyline.odm.models.tagging import Tagging
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

cl_engine = forge.get_classification()


class ConfigExtractor(ServiceBase):
    """ Runs parsers derived from MWCP, CAPE
    """
    HEURISTICS_MAP = dict(
        malware=1,
        safe=2,
    )
    def __init__(self, config=None):
        super(ConfigExtractor, self).__init__(config)
        self.file_parsers = None
        self.tag_parsers = None
        self.parser_classification = []  # default should be the classification set for the service.
        self.mwcp_reporter = cli.register()

    def start(self):
        # ==================================================================
        # On Startup actions:
        self.log.info(f"start() from {self.service_attributes.name} service called")
        yara_externals = {f'al_{x.replace(".", "_")}': "" for x in Tagging.flat_fields().keys()}
        file_parsers, tag_parsers = cli.compile(yara_externals)
        self.log.info(f"loaded {file_parsers}")
        cli.validate_parser_config()
        self.file_parsers = file_parsers
        self.tag_parsers = tag_parsers
    def classificationChecker(self, res_section, parser_name, file_parsers):

        for name, parser_obj in file_parsers.items():
            if name == parser_name:
                res_section.classification = cl_engine.normalize_classification(parser_obj.classification)
        return res_section

    def sectionBuilder(self, parser, field_dict, result, parsertype="MWCP"):

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

        parser_section = self.classificationChecker(parser_section, parser, self.file_parsers)
        fields_liststrings = {"address": "network.dynamic.uri", "c2_url": "network.dynamic.uri",
                              "c2_address": "network.dynamic.uri", "registrypath": "dynamic.registry_key",
                              "servicename": "", "filepath": "file.path", "missionid": "",
                              "version": "file.pe.versions.description",
                              "injectionprocess": "", "mutex": "dynamic.mutex", "directory": "",
                              "servicedisplayname": "",
                              "servicedescription": "", "key": "", "username": "file.string.extracted",
                              "password": "file.string.extracted", "email_address": "", "event": "", "filename": "",
                              "guid": "", "interval": "", "pipe": "", "proxy_address": "", "registrydata": "",
                              "servicedll": "", "serviceimage": "", "ssl_cert_sha1": "", "url": "", "urlpath": "",
                              "useragent": ""}
        if len(field_dict) > 0:  # if any decoder output exists raise heuristic
            parser_section.set_body(json.dumps(json_body), body_format=BODY_FORMAT.KEY_VALUE)
            parser_section.set_heuristic(self.HEURISTICS_MAP.get(category, 1), attack_id=mitre_att)
            parser_section.add_tag("source", parsertype)
            parser_section.add_tag('attribution.implant', malware_name.upper())
            if mitre_group :
                parser_section.add_tag('attribution.actor', mitre_group.upper())
            for malware_type in malware_types:
                parser_section.add_tag('attribution.family', malware_type.upper())
        fields_dictstrings = {"other": "file.config"}
        fields_liststringtuples = {"port": "network.dynamic.port", "socketaddress": "", "c2_socketaddress": "",
                                   "credential": "", "ftp": "", "listenport": "", "outputfile": "", "proxy": "",
                                   "proxy_socketaddress": "", "registrypathdata": "", "rsa_private_key": "",
                                   "rsa_public_key": "", "service": ""}
        for field, tag in fields_liststrings.items():
            if field in field_dict:
                generic_section = ResultSection(f" {field.capitalize()}  ")
                for line in field_dict[field]:
                    generic_section.add_line(f"{line}")
                if tag:
                    for x in field_dict[field]:
                        generic_section.add_tag(tag, x)
                parser_section.add_subsection(generic_section)

        for field, tag in fields_dictstrings.items():
            if field in field_dict:
                other_section = ResultSection(f"Other metadata found ", body_format=BODY_FORMAT.KEY_VALUE,
                                              body=json.dumps(field_dict["other"]))

                parser_section.add_subsection(other_section)

        for field, tag in fields_liststringtuples.items():
            if field in field_dict:
                generic_section = ResultSection(f"{field.capitalize()} Section ")
                for lst in field_dict[field]:
                    generic_section.add_lines(lst)
                if tag:
                    for x in field_dict[field]:
                        generic_section.add_tag(tag, x)
                parser_section.add_subsection(generic_section)
        for field in field_dict:
            if field not in fields_liststrings:
                self.log.debug(f"\n\n Couldn't add {field} ")
        result.add_section(parser_section)

    def execute(self, request):
        # ==================================================================
        # Execute a request:
        result = Result()
        # clear metadata from previous submision since ratdecoder run doesn't clear metadata
        self.mwcp_reporter._Reporter__reset()
        # Run Ratdecoders
        output = cli.run_ratdecoders(request.file_path, self.mwcp_reporter)
        if type(output) is dict:
            for parser, fields in output.items():
                self.sectionBuilder(parser, fields, result, "RATDecoder")
            self.log.info(output)
        elif type(output) is str:
            self.log.info(output)

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
            self.sectionBuilder(parser, field_dict, result)
        fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
        with os.fdopen(fd, "w") as myfile:
            myfile.write(json.dumps(output))
            myfile.write(json.dumps(output_fields))
        request.add_supplementary(temp_path, "output.json", "This is MWCP output as a JSON file")

        request.result = result
