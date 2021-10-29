import os
import json
import pytest
import shutil

from mwcp import metadata

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
samples = [ dict(
    sid=1,
    metadata={},
    service_name='configextractor',
    service_config={},
    fileinfo=dict(
        magic='ASCII text, with no line terminators',
        md5='fda4e701258ba56f465e3636e60d36ec',
        mime='text/plain',
        sha1='af2c2618032c679333bebf745e75f9088748d737',
        sha256='c805d89c6d26e6080994257d549fd8fec2a894dd15310053b0b8078064a5754b',
        size=19,
        type='unknown',
    ),
    filename='c805d89c6d26e6080994257d549fd8fec2a894dd15310053b0b8078064a5754b',
    min_classification='TLP:WHITE',
    max_files=501,  # TODO: get the actual value
    ttl=3600,
    ),
]


def create_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if not os.path.exists(temp_service_config_path):
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)


def remove_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if os.path.exists(temp_service_config_path):
        os.remove(temp_service_config_path)


def return_result_section_class():
    create_tmp_manifest()
    from assemblyline_v4_service.common.result import ResultSection
    remove_tmp_manifest()
    return ResultSection


@pytest.fixture
def class_instance():
    create_tmp_manifest()
    try:
        from configextractor import ConfigExtractor
        yield ConfigExtractor()
    finally:
        remove_tmp_manifest()


@pytest.fixture
def parsers():
    from assemblyline.odm.models.tagging import Tagging
    from cli import compile
    correct_yara_externals = {f'al_{x.replace(".", "_")}': "" for x in Tagging.flat_fields().keys()}
    return compile(correct_yara_externals)


def get_section_builder_inputs() -> list:
    possible_inputs_for_section_builder = []
    parser_names = ['Azorult', 'BitPaymer', 'ChChes', 'DoppelPaymer', 'Emotet',
                    'Enfal', 'EvilGrab', 'HttpBrowser', 'IcedID', 'RCSession',
                    'RedLeaf', 'Redsip', 'Retefe', 'SmokeLoader', 'QakBot']
    parser_types = ["MWCP", "RATDecoder"]
    field_dict = {
        "address": ['999'],
        "other": {
            "a": "b"
        },
        "not_in_field_map": True
    }
    for parser_name in parser_names:
        for parser_type in parser_types:
            possible_inputs_for_section_builder.append((parser_name, field_dict, parser_type))
    return possible_inputs_for_section_builder


def get_classification_checker_inputs() -> list:
    ResultSection = return_result_section_class()

    data_for_result_sections = get_section_builder_inputs()
    possible_inputs_for_classification_checker = []
    for parser_name, field_dict, parser_type in data_for_result_sections:
        res_sec = ResultSection(f"{parser_type} : {parser_name}")
        possible_inputs_for_classification_checker.append((res_sec, parser_name))
    return possible_inputs_for_classification_checker


def get_subsection_builder_inputs() -> list:
    ResultSection = return_result_section_class()

    parent_result_section = ResultSection("parent")
    field_dict = {
        "address": ["list_sample"],
        "c2_address": [["nested_list_sample"]],
        "c2_url": [["nested_list_sample"], "list_sample"]
    }
    possible_inputs_for_subsection_builder = [(parent_result_section, field_dict)]
    return possible_inputs_for_subsection_builder


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        heuristic_equality = this.heuristic.definition.attack_id == that.heuristic.definition.attack_id and \
                             this.heuristic.definition.classification == that.heuristic.definition.classification and \
                             this.heuristic.definition.description == that.heuristic.definition.description and \
                             this.heuristic.definition.filetype == that.heuristic.definition.filetype and \
                             this.heuristic.definition.heur_id == that.heuristic.definition.heur_id and \
                             this.heuristic.definition.id == that.heuristic.definition.id and \
                             this.heuristic.definition.max_score == that.heuristic.definition.max_score and \
                             this.heuristic.definition.name == that.heuristic.definition.name and \
                             this.heuristic.definition.score == that.heuristic.definition.score and \
                             this.heuristic.definition.signature_score_map == \
                             that.heuristic.definition.signature_score_map

        result_heuristic_equality = heuristic_equality and \
                                    this.heuristic.attack_ids == that.heuristic.attack_ids and \
                                    this.heuristic.frequency == that.heuristic.frequency and \
                                    this.heuristic.heur_id == that.heuristic.heur_id and \
                                    this.heuristic.score == that.heuristic.score and \
                                    this.heuristic.score_map == that.heuristic.score_map and \
                                    this.heuristic.signatures == that.heuristic.signatures

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = result_heuristic_equality and \
                               this.body == that.body and \
                               this.body_format == that.body_format and \
                               this.classification == that.classification and \
                               this.depth == that.depth and \
                               len(this.subsections) == len(that.subsections) and \
                               this.title_text == that.title_text

    if not current_section_equality:
        return False

    for index, subsection in enumerate(this.subsections):
        subsection_equality = check_section_equality(subsection, that.subsections[index])
        if not subsection_equality:
            return False

    return True


def check_reporter_equality(this, that) -> bool:
    # Checks all mwcp.Report attributes except for managed_tempdir
    reporter_equality = this.errors == that.errors and this.finalized == that.finalized \
                        and this.input_file == that.input_file \
                        and {x: sorted(this.metadata[x]) for x in this.metadata.keys()} == that.metadata \
                        and this.parser == that.parser
    if not reporter_equality:
        return reporter_equality

    # Also in the case where a metadata list exists, the order does not matter, so check as such
    metadata_equality = this.metadata.keys() == that.metadata.keys()
    if not metadata_equality:
        return metadata_equality

    for key, value in this.metadata.items():
        if not metadata_equality:
            return metadata_equality
        if type(value) == list:
            if len(value) != len(that.metadata[key]):
                return False
            for item in value:
                if item not in that.metadata[key]:
                    return False
        else:
            metadata_equality = value == that.metadata[key]

    return reporter_equality and metadata_equality


def create_correct_result_section_tree(fields, parsers=None, parser_type=None, parser_name=None):
    from configextractor import FIELD_TAG_MAP, tag_network_ioc
    from assemblyline_v4_service.common.result import BODY_FORMAT
    from assemblyline.common import forge
    cl_engine = forge.get_classification()
    ResultSection = return_result_section_class()
    other_key = "other"
    ratdecoder = "RATDecoder"
    mwcp = "MWCP"
    malware_name = ''
    malware_types = []
    mitre_group = ''
    mitre_att = ''
    category = 'malware'
    correct_file_parsers = {}

    if not parser_type or parser_type not in [ratdecoder, mwcp] or not parser_name:
        correct_parent_section = ResultSection("parent")
    else:
        correct_file_parsers = parsers[0]
        correct_parent_section = ResultSection(f"{parser_type} : {parser_name}")

    parser_attributes = {}
    if parser_type == mwcp:
        obj = correct_file_parsers[parser_name]
        for item in ['classification', 'mitre_group', 'mitre_att',
                     'malware', 'malware_types', 'category']:
            val = getattr(obj, item, None)
            if val:
                parser_attributes[item] = val
        malware_name = obj.malware
        malware_types = obj.malware_types
        mitre_att = obj.mitre_att
        mitre_group = obj.mitre_group
        category = obj.category
    elif parser_type == ratdecoder:
        malware_name = parser_name

    if correct_file_parsers:
        parser_classification = correct_file_parsers[parser_name].classification
        correct_classification = cl_engine.normalize_classification(parser_classification)
        correct_parent_section.classification = correct_classification

    if fields and parser_type:
        from configextractor import HEURISTICS_MAP
        correct_parent_section.set_body(json.dumps(parser_attributes), body_format=BODY_FORMAT.KEY_VALUE)
        correct_parent_section.set_heuristic(HEURISTICS_MAP.get(category, 1), attack_id=mitre_att)
        correct_parent_section.add_tag("source", parser_type)
        if malware_name:
            correct_parent_section.add_tag('attribution.implant', malware_name.upper())
        if mitre_group:
            correct_parent_section.add_tag('attribution.actor', mitre_group.upper())
        for malware_type in malware_types:
            correct_parent_section.add_tag('attribution.family', malware_type.upper())

    # subsection section
    for key, value in fields.items():
        if key in FIELD_TAG_MAP:
            tag = FIELD_TAG_MAP[key]
            body = []
            for field in value:
                if type(field) is str:
                    body.append({key: field})
                elif type(field) is list:
                    body.extend([{key: item} for item in field])

            correct_subsection = ResultSection(
                title_text=f"Extracted {key.capitalize()}",
                body=json.dumps(body),
                body_format=BODY_FORMAT.TABLE,
            )
            if 'uri' in tag:
                tag_network_ioc(correct_subsection, value)
            else:
                for v in value:
                    correct_subsection.add_tag(tag, value)
            correct_parent_section.add_subsection(correct_subsection)

    # Other key section comes after all subsection builder
    if other_key in fields:
        other_content = fields[other_key]
        other_section = ResultSection(
            title_text=f"Other metadata found",
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(other_content)
        )
        correct_parent_section.add_subsection(other_section)
    return correct_parent_section


def yield_sample_file_paths():
    samples_path = os.path.join(TEST_DIR, "samples")
    # For some reason os.listdir lists the same file twice, but with a trailing space on the second entry
    paths = set([path.rstrip() for path in os.listdir(samples_path)])
    for sample in paths:
        yield os.path.join(samples_path, sample)


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
        assert class_instance.mwcp_report is None

    @staticmethod
    def test_start(class_instance, parsers):
        correct_file_parsers, correct_tag_parsers = parsers
        class_instance.start()
        # Check if indeed the expected file and tag parsers are the actual file and tag parsers
        assert class_instance.file_parsers == correct_file_parsers
        assert class_instance.tag_parsers == correct_tag_parsers

    @staticmethod
    @pytest.mark.parametrize("sample",
        samples
    )
    def test_execute(sample, class_instance):
        # Imports required to execute the sample
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest

        # Creating the required objects for execution
        service_task = ServiceTask(sample)
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

        # Avoiding unique items in the response
        test_result_response = test_result.pop("response")
        correct_result_response = correct_result.pop("response")
        assert test_result == correct_result

        # Comparing everything in the response except for the service_completed and the output.json supplementary
        test_result_response["milestones"].pop("service_completed")
        correct_result_response["milestones"].pop("service_completed")
        correct_result_response.pop("supplementary")
        test_result_response.pop("supplementary")


        assert test_result_response == correct_result_response

    @staticmethod
    @pytest.mark.parametrize("parser,field_dict,parsertype",
                             get_section_builder_inputs()
                             )
    def test_section_builder(parser, field_dict, parsertype, class_instance, parsers):
        from assemblyline_v4_service.common.result import Result
        result = Result()
        correct_tag_parsers = parsers[0]
        correct_sections = create_correct_result_section_tree(field_dict, parsers, parsertype, parser)
        class_instance.file_parsers = correct_tag_parsers
        class_instance.section_builder(parser=parser, field_dict=field_dict, result=result, parsertype=parsertype)

        assert check_section_equality(result.sections[0], correct_sections)

    @staticmethod
    @pytest.mark.parametrize("res_section,parser_name",
                             get_classification_checker_inputs()
                             )
    def test_classification_checker(res_section, parser_name, parsers):
        from configextractor import classification_checker
        from assemblyline.common import forge
        cl_engine = forge.get_classification()

        correct_file_parsers = parsers[0]
        parser_classification = correct_file_parsers[parser_name].classification
        correct_classification = cl_engine.normalize_classification(parser_classification)

        # TODO: Note that classification_checker() only needs the parser classification for the passed parser_name,
        #  not all parsers
        test_res_section = classification_checker(res_section=res_section,
                                                  parser_name=parser_name, file_parsers=correct_file_parsers)
        assert test_res_section.classification == correct_classification

    @staticmethod
    @pytest.mark.parametrize("parent_section,fields",
                             get_subsection_builder_inputs()
                             )
    def test_subsection_builder(parent_section, fields):
        from configextractor import subsection_builder
        correct_parent_section = create_correct_result_section_tree(fields)
        subsection_builder(parent_section=parent_section, fields=fields)
        assert check_section_equality(parent_section, correct_parent_section)


def get_parser_entries():
    import yaml
    from cli import YARA_PARSER_PATH
    stream = open(YARA_PARSER_PATH, 'r')
    parser_entries = yaml.full_load(stream)
    return parser_entries


def get_validate_parser_inputs():
    possible_inputs_for_validate_parser = []
    parser_entries = get_parser_entries()
    incorrect_key = "incorrect"

    for parser_entry in parser_entries.values():
        possible_inputs_for_validate_parser.append(parser_entry["parser"])
    possible_inputs_for_validate_parser.append([{incorrect_key: [incorrect_key]}])
    return possible_inputs_for_validate_parser


def get_report():
    import mwcp
    from cli import MWCP_PARSERS_DIR_PATH
    mwcp.register_entry_points()
    mwcp.register_parser_directory(MWCP_PARSERS_DIR_PATH)
    reporter = mwcp.Report()
    return reporter


def add_metadata(data, mwcp_key, correct_report=None):
    if not correct_report:
        correct_report = get_report()
    for val in data.values():
        correct_report.add_metadata(mwcp_key, val)
    return correct_report


def create_correct_parser_objs(tags=None):
    import yara
    from cli import check_paths, validate_parsers, Parser

    parser_entries = get_parser_entries()
    parser_objs = {}
    for parser_name, parser_details in parser_entries.items():
        rule_source_paths = []
        # if tags are present then get tag rule paths

        if tags and 'tag' in parser_details['selector']:
            rule_source_paths = parser_details['selector']['tag']
        elif not tags and 'yara_rule' in parser_details['selector']:
            rule_source_paths = parser_details['selector']['yara_rule']
        if not check_paths(rule_source_paths):
            continue
        validated_parsers = validate_parsers(parser_details['parser'])
        compiled_rules = []
        for rule_source_path in rule_source_paths:
            abs_path = os.path.join(ROOT_DIR, rule_source_path)
            if tags:
                rule = yara.compile(filepath=abs_path, externals=tags)
            else:
                rule = yara.compile(filepath=abs_path)
            compiled_rules.append(rule)
        parser_objs[parser_name] = Parser(
            name=parser_name,
            parser_list=validated_parsers,
            compiled_rules=compiled_rules,
            classification=parser_details['classification'],
            malware=parser_details['malware'],
            malware_types=parser_details['malware_type'],
            mitre_group=parser_details['mitre_group'],
            mitre_att=parser_details['mitre_att'],
            category=parser_details['category'],
            run_on=parser_details['run_on']
        )
    return parser_objs


def get_tags():
    from assemblyline.odm.models.tagging import Tagging
    return {f'al_{x.replace(".", "_")}': "" for x in Tagging.flat_fields().keys()}


def get_new_tags():
    request_task_tags = {"a": "b"}

    tags = {f"al_{k.replace('.', '_')}": i for k, i in request_task_tags.items()}
    newtags = {}
    # yara externals must be dicts w key value pairs being strings
    for k, v in tags.items():
        key = f"al_{k.replace('.', '_')}"
        for i in range(len(v)):
            if not isinstance(v[i], str):
                v[i] = str(v[i])
        value = " | ".join(v)
        newtags[key] = value
    return newtags
