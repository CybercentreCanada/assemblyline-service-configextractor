import json
import os
import cli
from assemblyline.odm.models.tagging import Tagging
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT


class ConfigExtractor(ServiceBase):
    """ Runs parsers derived from MWCP, CAPE
    """
    def __init__(self, config=None):
        super(ConfigExtractor, self).__init__(config)


    def start(self):
        # ==================================================================
        # On Startup actions:
        self.log.info(f"start() from {self.service_attributes.name} service called")

    def execute(self, request):
        # ==================================================================
        # Execute a request:
        dirname = os.path.dirname(__file__)
        
        result = Result()
        output_section = ResultSection('Output of ConfigExtractor')
        output='test'
        tags = {f"al_{k.replace('.', '_')}": i for k, i in request.task.tags.items()}       
        print(type(tags))
        tags = {f"al_{k.replace('.', '_')}": i for k, i in (Tagging.flat_fields().items())}
        print(tags,"\n\n")
        print(tags['al_attribution_actor'])

        #print(list(Tagging.flat_fields().keys()))
        #for i,v in tags.items():
         #   print(i,v)
        cli.start(request.file_path,tags)
        
        output_section.add_line(output)
        result.add_section(output_section)
        request.result = result