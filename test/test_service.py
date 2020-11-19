import os
import json
import pytest
import shutil

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
sample1 = dict(
    sid=1,
    metadata={},
    service_name='configextractor',
    service_config={},
    fileinfo=dict(
        magic='ASCII text, with no line terminators',
        md5='1f09ecbd362fa0dfff88d4788e6f5df0',
        mime='text/plain',
        sha1='a649bf201cde05724e48f2d397a615b201be34fb',
        sha256='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
        size=19,
        type='unknown',
    ),
    filename='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
    min_classification='TLP:WHITE',
    max_files=501,  # TODO: get the actual value
    ttl=3600,
)


@pytest.fixture
def class_instance():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    try:
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)

        from configextractor import ConfigExtractor
        yield ConfigExtractor()
    finally:
        # Delete the service_manifest.yml
        os.remove(temp_service_config_path)


@pytest.fixture
def parsers():
    from assemblyline.odm.models.tagging import Tagging
    from cli import compile
    correct_yara_externals = {f'al_{x.replace(".", "_")}': "" for x in Tagging.flat_fields().keys()}
    return compile(correct_yara_externals)


def possible_inputs_for_section_builder() -> list:
    POSSIBLE_INPUTS_FOR_SECTION_BUILDER = []
    PARSER_NAMES = ['Azorult', 'BitPaymer', 'ChChes', 'DoppelPaymer', 'Emotet',
                    'Enfal', 'EvilGrab', 'HttpBrowser', 'IcedID', 'RCSession',
                    'RedLeaf', 'Redsip', 'Retefe', 'SmokeLoader', 'QakBot']
    PARSER_TYPES = ["MWCP", "RATDecoder"]
    FIELD_DICTS = [
        {
            "other": {
                "a": "b"
            },
            "not_in_field_map": True
        }
    ]
    for parser_name in PARSER_NAMES:
        for parser_type in PARSER_TYPES:
            for field_dict in FIELD_DICTS:
                POSSIBLE_INPUTS_FOR_SECTION_BUILDER.append((parser_name, field_dict, parser_type))
    return POSSIBLE_INPUTS_FOR_SECTION_BUILDER


def possible_inputs_for_classification_checker() -> list:
    POSSIBLE_INPUTS_FOR_CLASSIFICATION_CHECKER = []
    # TODO: Set this up
    return POSSIBLE_INPUTS_FOR_CLASSIFICATION_CHECKER


class TestConfigExtractor:

    @classmethod
    def setup_class(cls):
        # Placing the samples in the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            sample_path = os.path.join(samples_path, sample)
            shutil.copyfile(sample_path, os.path.join("/tmp", sample))

    @classmethod
    def teardown_class(cls):
        # Cleaning up the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            temp_sample_path = os.path.join("/tmp", sample)
            os.remove(temp_sample_path)

    @staticmethod
    def test_init(class_instance):
        from cli import register
        assert class_instance.file_parsers == {}
        assert class_instance.tag_parsers is None
        assert class_instance.parser_classification == []
        assert class_instance.mwcp_reporter.__dict__ == register().__dict__

    @staticmethod
    def test_start(class_instance, parsers):
        correct_file_parsers, correct_tag_parsers = parsers
        class_instance.start()
        # Check if indeed the expected file and tag parsers are the actual file and tag parsers
        assert class_instance.file_parsers == correct_file_parsers
        assert class_instance.tag_parsers == correct_tag_parsers

    @staticmethod
    @pytest.mark.parametrize("sample", [
        sample1
    ])
    def test_execute(sample, class_instance):
        # Imports required to execute the sample
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest

        # Creating the required objects for execution
        service_task = ServiceTask(sample1)
        task = Task(service_task)
        class_instance._task = task
        service_request = ServiceRequest(task)

        # Actually executing the sample
        # task.service_config = {<put service config here>}
        class_instance.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
        with open(correct_result_path, "r") as f:
            correct_result = json.loads(f.read())
        f.close()

        # Assert that the appropriate sections of the dict are equal

        # Avoiding date in the response
        test_result_response = test_result.pop("response")
        correct_result_response = correct_result.pop("response")
        assert test_result == correct_result

        # Comparing everything in the response except for the date and the output.json path
        test_result_response["milestones"].pop("service_completed")
        correct_result_response["milestones"].pop("service_completed")
        test_result_response["supplementary"][0].pop("path")
        correct_result_response["supplementary"][0].pop("path")

        assert test_result_response == correct_result_response

    # TODO: Incorporate field_dict into POSSIBLE_INPUTS
    @staticmethod
    @pytest.mark.parametrize("parser,field_dict,parsertype",
        possible_inputs_for_section_builder()
    )
    def test_section_builder(parser, field_dict, parsertype, class_instance, parsers):
        from assemblyline_v4_service.common.result import Result
        result = Result()
        correct_tag_parsers = parsers[0]
        class_instance.file_parsers = correct_tag_parsers
        class_instance.section_builder(parser=parser, field_dict=field_dict, result=result, parsertype=parsertype)
        # TODO: Compare result object attributes
        pass

    @staticmethod
    @pytest.mark.parametrize("res_section,parser_name,file_parsers",
        possible_inputs_for_classification_checker()
    )
    def test_classification_checker(res_section, parser_name, file_parsers):
        from configextractor import classification_checker
        from assemblyline_v4_service.common.result import ResultSection
        # ResultSection()
        test_res_section = classification_checker(res_section=res_section, parser_name=parser_name, file_parsers=file_parsers)
        # assert test_res_section == correct_res_section
        pass

    # @staticmethod
    # @pytest.mark.parametrize("parent_section,fields", [
    #     (None, {})
    # ])
    # def test_subsection_builder(parent_section, fields):
    #     from configextractor import subsection_builder
    #     subsection_builder(parent_section=parent_section, fields=fields)
    #     pass

    # TODO: Complete unit tests for cli.py static methods
# class TestCLI: