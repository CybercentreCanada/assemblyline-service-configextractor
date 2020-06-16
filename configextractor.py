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

    def start(self):
        # ==================================================================
        # On Startup actions:
        self.log.info(f"start() from {self.service_attributes.name} service called")
        yara_externals = {f'al_{x.replace(".", "_")}': "" for x in Tagging.flat_fields().keys()}
        file_parsers, tag_parsers = cli.compile(yara_externals)
        cli.validate_parser_config()
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
        print('starting execute')
        result = Result()

        tags = {f"al_{k.replace('.', '_')}": i for k, i in request.task.tags.items()}
        print('tags from last service are', tags)
        # newtags = {f"al_{k.replace('.', '_')}": " | ".join(i) for k, i in request.task.tags.items()}
        tags = {'file.path': ['C:\wp-includes\`{,20}.dgll'], 'file.plist.cf_bundle.version.long': ['government'],
                'file.plist.cf_bundle.pkg_type': ['complex'], 'file.date.last_modified': ['stays', 'and'],
                'file.swf.header.frame.rate': ['provide', 'this'], 'file.name.anomaly': ['support', 'more'],
                'file.pe.exports.function_name': ['new_country_environment.gif'],
                'file.pe.versions.description': ['website', 'industry'],
                'file.pdf.stats.sha1': ['f0066cbb4a2bed25e2c4e7e23a80e12c7e319dea',
                                        '7c87e78194a050ffe1e16c4734a0e04080f738ad'],
                'file.behavior': ['or', 'marketplace'], 'file.rule.yara': ['environment', 'environment'],
                'av.virus_name': ['working_and_engaging.jpg', 'performs_invite.jpg'],
                'attribution.family': ['Canada', 'from'], 'attribution.implant': ['innovative', 'do'],
                'attribution.actor': ['in', 'on'], 'cert.valid.end': ['working', 'new'],
                'info.phone_number': ['+1 859-890-8024', '+1 686-971-9520'], 'technique.string': ['potential'],
                'network.dynamic.domain': ['certain.com', 'an.biz'], 'network.port': [2662],
                'network.static.uri': ['ftp://enhanced.ca/assist/survey/government/product/determine/are']}
        newtags = {}
        # yara externals must be dicts w key value pairs being strings
        for k, v in tags.items():
            key = f"al_{k.replace('.', '_')}"
            for i in range(len(v)):
                if not isinstance(v[i], str):
                    v[i] = str(v[i])
            value = " | ".join(v)
            newtags[key] = value
        # tag_section = ResultSection('Test Tags', body_format=BODY_FORMAT.KEY_VALUE,
        #                            body=json.dumps(tags))
        # tag_section.add_tag("network.dynamic.ip", "192.146.251.69")
        # result.add_section(tag_section)

        # get matches for both, dedup then run
        parsers = cli.deduplicate(self.file_parsers, self.tag_parsers, request.file_path, newtags)
        example_fields = cli.run(parsers, request.file_path)

        for parser, field_dict in example_fields.items():
            field_dict = {'other': {
                'RSA public key': '-----BEGIN PUBLIC KEY-----\nMHwwDQYJKoZIhvcNAQEBBQADawAwaAJhALk+KlHgOKXm9eDkWu2yN9lanjwOm6W2\nPV0tgr4msNVby2pOJ6S1MZQnQwxl7y6WWzT4kveAQhLmW8JB2M2PDOxZOgVMJH2C\nAtkVW1p/P9jNJWVvjK9SmrbLdIeiKNtRfQIDAQAB\n-----END PUBLIC KEY-----'},
                          'address': ['80.11.163.139:443', '85.54.169.141:8080', '185.14.187.201:8080',
                                      '45.79.188.67:8080', '63.142.253.122:8080', '24.51.106.145:21',
                                      '91.205.215.66:8080', '222.214.218.192:8080', '80.11.163.139:21',
                                      '190.108.228.48:990', '88.247.163.44:80', '88.156.97.210:80',
                                      '95.128.43.213:8080', '211.63.71.72:8080', '182.176.132.213:8090',
                                      '182.176.106.43:995', '186.4.172.5:8080', '178.79.161.166:443',
                                      '101.187.237.217:20', '136.243.177.26:8080', '181.31.213.158:8080',
                                      '87.106.139.101:8080', '41.220.119.246:80', '206.189.98.125:8080',
                                      '190.18.146.70:80', '45.33.49.124:443', '187.144.189.58:50000',
                                      '189.209.217.49:80', '87.230.19.21:8080', '212.71.234.16:8080',
                                      '181.143.53.227:21', '217.160.182.191:8080', '186.4.172.5:443',
                                      '104.236.246.93:8080', '190.106.97.230:443', '103.97.95.218:143',
                                      '178.254.6.27:7080', '92.233.128.13:143', '188.166.253.46:8080',
                                      '94.205.247.10:80', '115.78.95.230:443', '169.239.182.217:8080',
                                      '37.157.194.134:443', '104.131.11.150:8080', '45.123.3.54:443',
                                      '5.196.74.210:8080', '179.32.19.219:22', '78.24.219.147:8080', '85.104.59.244:20',
                                      '201.251.43.69:8080', '190.228.72.244:53', '103.255.150.84:80',
                                      '92.222.216.44:8080', '173.212.203.26:8080', '182.76.6.2:8080',
                                      '124.240.198.66:80', '190.53.135.159:21', '46.105.131.87:80', '190.226.44.20:21',
                                      '190.211.207.11:443', '199.19.237.192:80', '186.75.241.230:80', '186.4.172.5:20',
                                      '149.167.86.174:990', '149.202.153.252:8080', '87.106.136.232:8080',
                                      '78.188.105.159:21', '83.136.245.190:8080', '181.143.194.138:443',
                                      '159.65.25.128:8080', '86.98.25.30:53', '85.106.1.166:50000',
                                      '138.201.140.110:8080', '185.94.252.13:443', '142.44.162.209:8080',
                                      '92.222.125.16:7080', '27.4.80.183:443', '190.186.203.55:80',
                                      '200.71.148.138:8080', '31.12.67.62:7080', '31.172.240.91:8080',
                                      '62.75.187.192:8080', '144.139.247.220:80', '27.147.163.188:8080',
                                      '217.145.83.44:80', '119.15.153.237:80', '47.41.213.2:22', '190.145.67.134:8090']}
            self.sectionBuilder(field_dict, result, parser)
        # output_section = ResultSection('Output of ConfigExtractor')
        # output_section.add_line("mwcp output here")
        # result.add_section(output_section)

        fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
        with os.fdopen(fd, "w") as myfile:
            myfile.write(json.dumps(example_fields))
        request.add_supplementary(temp_path, "output.json", "This is MWCP output as a JSON file")

        request.result = result
