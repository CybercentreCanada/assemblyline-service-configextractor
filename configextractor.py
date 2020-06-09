import cli
import json
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
        self.file_parsers = file_parsers
        self.tag_parsers = tag_parsers

    def execute(self, request):
        # ==================================================================
        # Execute a request:
        print('starting execute')
        result = Result()
        output_section = ResultSection('Output of ConfigExtractor')
        tags = {f"al_{k.replace('.', '_')}": i for k, i in request.task.tags.items()}
        print('tags from last service are', tags)
        #newtags = {f"al_{k.replace('.', '_')}": " | ".join(i) for k, i in request.task.tags.items()}
        tags = {'file.path':['C:\wp-includes\`{,20}.dll'],'file.plist.cf_bundle.version.long': ['government'], 'file.plist.cf_bundle.pkg_type': ['complex'], 'file.date.last_modified': ['stays', 'and'], 'file.swf.header.frame.rate': ['provide', 'this'], 'file.name.anomaly': ['support', 'more'], 'file.pe.exports.function_name': ['new_country_environment.gif'], 'file.pe.versions.description': ['website', 'industry'], 'file.pdf.stats.sha1': ['f0066cbb4a2bed25e2c4e7e23a80e12c7e319dea', '7c87e78194a050ffe1e16c4734a0e04080f738ad'], 'file.behavior': ['or', 'marketplace'], 'file.rule.yara': ['environment', 'environment'], 'av.virus_name': ['working_and_engaging.jpg', 'performs_invite.jpg'], 'attribution.family': ['Canada', 'from'], 'attribution.implant': ['innovative', 'do'], 'attribution.actor': ['in', 'on'], 'cert.valid.end': ['working', 'new'], 'info.phone_number': ['+1 859-890-8024', '+1 686-971-9520'], 'technique.string': ['potential'], 'network.dynamic.domain': ['certain.com', 'an.biz'], 'network.port': [2662], 'network.static.uri': ['ftp://enhanced.ca/assist/survey/government/product/determine/are']}
        newtags={}
        # yara externals must be dicts w key value pairs being strings
        for k,v in tags.items():
            key = f"al_{k.replace('.','_')}"
            for i in range(len(v)):
                if not isinstance(v[i] ,str):
                    v[i] = str(v[i])
            value = " | ".join(v)
            newtags[key] = value
        tag_section = ResultSection('Test Tags', body_format=BODY_FORMAT.KEY_VALUE,
                                       body=json.dumps(tags))
        result.add_section((tag_section))

        # get matches for both, dedup then run
        parsers = cli.deduplicate(self.file_parsers, self.tag_parsers, request.file_path, newtags)
        output_dict = cli.run(parsers, request.file_path)
        #TODO  create subsections for each parser output
        #TODO standardize output into mwcp format
        for k,v in output_dict.items():
            if len(v) > 27:
                output_section.add_line(k)
                output_section.add_line(v)
                print(len(v),v)
        result.add_section(output_section)
        request.result = result