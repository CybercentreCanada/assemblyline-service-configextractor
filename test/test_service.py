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
    from configextractor import FIELD_TAG_MAP
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
            tags = None
            tag = FIELD_TAG_MAP[key]
            if tag:
                tags = {tag: value}
            body = []
            for field in value:
                if type(field) is str:
                    body.append({key: field})
                elif type(field) is list:
                    body.extend([{key: item} for item in field])

            correct_subsection = ResultSection(
                title_text=f"Extracted {key.capitalize()}",
                tags=tags,
                body=json.dumps(body),
                body_format=BODY_FORMAT.TABLE,
            )
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


def get_reporter():
    import mwcp
    from cli import MWCP_PARSERS_DIR_PATH
    mwcp.register_entry_points()
    mwcp.register_parser_directory(MWCP_PARSERS_DIR_PATH)
    reporter = mwcp.Report()
    return reporter


def add_metadata(data, mwcp_key, correct_reporter=None):
    from mwcp import metadata
    if not correct_reporter:
        correct_reporter = get_reporter()
    for val in data.values():
        correct_reporter.add_metadata(mwcp_key, val)
    return correct_reporter


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


class TestCLI:
    @staticmethod
    @pytest.mark.parametrize("parser_list",
                             get_validate_parser_inputs()
                             )
    def test_validate_parsers(parser_list):
        from cli import validate_parsers
        mwcp_key = "MWCP"
        incorrect_key = "incorrect"
        correct_parser_set = set()
        incorrect_parser_set = set()
        for parser in parser_list:
            if mwcp_key in parser:
                correct_parser_set.update(parser[mwcp_key])
            else:
                incorrect_parser_set.update(parser[incorrect_key])
        correct_parser_list = list(correct_parser_set)
        incorrect_parser_list = list(incorrect_parser_set)

        if correct_parser_list:
            test_parser_list = validate_parsers(parser_list)
            assert test_parser_list == correct_parser_list
        if incorrect_parser_list:
            with pytest.raises(NameError):
                validate_parsers(parser_list)

    @staticmethod
    @pytest.mark.parametrize("paths",
                             [
                                 [],
                                 [""],
                                 ["fake_path"],
                                 ['./tag_rules/emotet.rule']
                             ]
                             )
    def test_check_paths(paths):
        from cli import check_paths
        if not paths:
            assert not check_paths(paths)
        for path in paths:
            abs_file_path = os.path.join(ROOT_DIR, path)
            if not path:
                with pytest.raises(Exception):
                    check_paths(paths)
            if not os.path.isfile(abs_file_path):
                with pytest.raises(Exception):
                    check_paths(paths)

    @staticmethod
    @pytest.mark.parametrize("tags",
                             [
                                 {},
                                 get_tags()
                             ]
                             )
    def test_initialize_parser_objs(tags):
        from cli import initialize_parser_objs
        correct_parser_objs = create_correct_parser_objs(tags)
        test_parser_objs = initialize_parser_objs(tags)
        assert test_parser_objs.keys() == correct_parser_objs.keys()
        for key in correct_parser_objs.keys():
            assert test_parser_objs[key] == correct_parser_objs[key]

    @staticmethod
    def test_validate_parser_config():
        from cli import validate_parser_config, MWCP_PARSER_PATHS, MWCP_PARSER_CONFIG_PATH, MWCP_PARSERS_DIR_PATH
        import yaml
        import filecmp
        # correct_parser_config_validation()
        yaml_parsers = {}
        # find name of parser class
        for parser in MWCP_PARSER_PATHS:
            file = open(parser, "r")
            for line in file:
                if line.partition("class ")[2].partition("(Parser):")[0]:
                    parser_class = line.partition("class ")[2].partition("(Parser):")[0]
                    entry = {
                        "description": f"{parser.stem} Parser",
                        "author": "Not Found",
                        "parsers": [f".{parser_class}"]
                    }
                    yaml_parsers[parser.stem] = entry
            file.close()
        parsers_in_config = []
        # check that all parsers in dir are present in mwcp config
        test_mwcp_parser_config = os.path.join(MWCP_PARSERS_DIR_PATH, "test_parser_config.yaml")
        with open(test_mwcp_parser_config, "w+", encoding='utf-8') as f:
            for entry, value in yaml_parsers.items():
                parsers_in_config.append(entry)
                p = {entry: value}
                yaml.dump(p, f)
        f.close()
        if not os.path.exists(test_mwcp_parser_config):
            assert False
        validate_parser_config()
        assert filecmp.cmp(test_mwcp_parser_config, MWCP_PARSER_CONFIG_PATH, shallow=False)
        os.remove(test_mwcp_parser_config)
        with pytest.raises(Exception):
            parsers_in_config.append('apythonfileinmwcp_parsers')
            assert filecmp.cmp(test_mwcp_parser_config, MWCP_PARSER_CONFIG_PATH, shallow=False)

    @staticmethod
    @pytest.mark.parametrize("f_path",
                             yield_sample_file_paths()
                             )
    def test_run(f_path, parsers):
        # TODO: need way to simulate actual malware so that parsers get matched
        from cli import run
        import mwcp
        correct_reporter = get_reporter()
        correct_outputs = {}
        correct_file_parsers = parsers[0]
        for parser in correct_file_parsers:
            mwcp.run(parser, file_path=f_path)
            if correct_reporter.metadata:
                correct_outputs[parser] = correct_reporter.metadata

        test_reporter = get_reporter()
        test_outputs = run(correct_file_parsers, f_path, test_reporter)
        assert test_outputs == correct_outputs

    @staticmethod
    @pytest.mark.parametrize("parsers",
                             [
                                 set(),
                                 {"item"}
                             ]
                             )
    def test_check_names(parsers):
        from cli import MWCP_PARSER_PATHS, check_names
        mwcp_parsers = set()
        for file in MWCP_PARSER_PATHS:
            mwcp_parsers.add(file.stem)
        diff = parsers - mwcp_parsers
        if diff:
            with pytest.raises(Exception):
                check_names(parsers)

    @staticmethod
    @pytest.mark.parametrize("file_path",
                             yield_sample_file_paths()
                             )
    def test_deduplicate(file_path, parsers):
        # TODO: this method needs a lot of work, specifically we need file paths for samples that would hit
        from cli import deduplicate, validate_parsers, check_names
        correct_parser_entries = get_parser_entries()
        correct_file_parsers, correct_tag_parsers = parsers

        super_parser_list = []
        and_malware = {}
        for correct_parser_key, correct_parser_value in correct_parser_entries.items():
            correct_parser_selector = correct_parser_value['selector']
            if 'wildcard' in correct_parser_selector:
                wildcard_parsers = validate_parsers(correct_parser_value['parser'])
                super_parser_list.extend(wildcard_parsers)
            if 'AND' in correct_parser_value['run_on']:  # everything else is OR by default
                if 'tag' in correct_parser_selector and 'yara_rule' in correct_parser_selector:
                    # then match must exist for some parser for both tag and file
                    malware_name = correct_parser_value['malware']
                    and_malware[malware_name] = correct_parser_key
                else:
                    raise Exception("AND cannot be specified without both tag and file yara rules")
        # for malware, top in and_malware.items():
        #     file_rules = correct_file_parsers[top].compiled_rules
        #     tag_rules = correct_tag_parsers[top].compiled_rules
        # TODO: figure out how to simulate all_rules_match since we can't access it here
        # file_bool = all_rules_match(file_rules)
        # tag_bool = all_rules_match(tag_rules)
        # if file_bool and tag_bool:
        #     print("both file and tag rules have match")
        # else:
        #     print('tag or file rule did not match, excluding...')
        #     malware_to_parsers = correct_file_parsers[top].parser_list
        #     super_parser_list = [x for x in super_parser_list if x not in malware_to_parsers]

        super_parser_list = [i[0].upper() + i[1:] for i in super_parser_list]
        super_parser_list_set = set(super_parser_list)
        check_names(super_parser_list_set)
        correct_super_parser_set_list = list(super_parser_list_set)

        newtags = get_new_tags()
        test_super_parser_set_list = deduplicate(correct_file_parsers, correct_tag_parsers, file_path, newtags)
        assert test_super_parser_set_list == correct_super_parser_set_list

    @staticmethod
    @pytest.mark.parametrize("tags",
                             [get_tags(), None]
                             )
    def test_compile(tags):
        from cli import compile
        correct_parser_objs = create_correct_parser_objs()
        correct_parser_objs_tags = None
        if tags:
            correct_parser_objs_tags = create_correct_parser_objs(tags)

        test_parser_objs, test_parser_objs_tags = compile(tags)
        assert test_parser_objs == correct_parser_objs
        assert test_parser_objs_tags == correct_parser_objs_tags

    @staticmethod
    def test_register():
        from cli import register
        correct_reporter = get_reporter()
        test_reporter = register()
        assert test_reporter.as_dict() == correct_reporter.as_dict()

    @staticmethod
    @pytest.mark.parametrize("data",
                             [
                                 {"val": "no_backslashes"},
                                 {"val": "\\backslashes"},
                                 {"val": ".period"},
                                 {"val": "localhost"},
                                 {"val": "localhost*"},
                             ]
                             )
    def test_check_for_backslashes(data):
        from cli import check_for_backslashes
        ta_key = "val"
        mwcp_key = "address"
        val = data[ta_key]
        correct_report = get_reporter()
        IGNORE_FIELD_LIST = ['localhost', 'localhost*']
        if '\\' in val:
            correct_report.add_metadata(mwcp_key, val)
        elif '.' not in val and val not in IGNORE_FIELD_LIST:
            correct_report.add_metadata(mwcp_key, val)

        test_report = get_reporter()
        check_for_backslashes(ta_key, mwcp_key, data, test_report)
        assert test_report.as_dict() == correct_report.as_dict()

    @staticmethod
    @pytest.mark.parametrize("output,scriptname,mwcp_key",
                             [
                                 ({}, 'unrecom', None),
                                 ({}, 'notunrecom', None),
                                 ({
                                     "Process Injection": "a",
                                     "Injection": "b",
                                     "Inject Exe": "c"
                                 }, "notunrecom", "injectionprocess"),
                                 ({
                                     "Screen Rec Link": "a",
                                     "WebPanel": "b",
                                     "Plugins": "c"
                                 }, "notunrecom", "url"),
                                 ({
                                      "Install Dir": "a",
                                      "InstallDir": "b",
                                      "InstallPath": "c",
                                      "Install Folder": "d",
                                      "Install Folder1": "e",
                                      "Install Folder2": "f",
                                      "Install Folder3": "g",
                                      "Folder Name": "h",
                                      "FolderName": "i",
                                      "pluginfoldername": "j",
                                      "nombreCarpeta": "k",
                                 }, "notunrecom", "directory"),
                                 ({
                                      "InstallName": "a",
                                      "Install Name": "b",
                                      "Exe Name": "c",
                                      "Jar Name": "d",
                                      "JarName": "e",
                                      "StartUp Name": "f",
                                      "File Name": "g",
                                      "USB Name": "h",
                                      "Log File": "i",
                                      "Install File Name": "j",
                                 }, "notunrecom", "filename"),
                                 ({
                                     "Campaign ID": "a",
                                     "CampaignID": "b",
                                     "Campaign Name": "c",
                                     "Campaign": "d",
                                     "ID": "e",
                                     "prefijo": "f",
                                 }, "notunrecom", "missionid"),
                                 ({
                                     "Version": "a",
                                     "version": "b",
                                 }, "notunrecom", "version"),
                                 ({
                                     "FTP Interval": "a",
                                     "Remote Delay": "b",
                                     "RetryInterval": "c"
                                 }, "unrecom", "interval"),
                                 ({
                                     "EncryptionKey": "a",
                                 }, "unrecom", "key"),
                                 ({
                                     "Mutex": "a",
                                     "mutex": "b",
                                     "Mutex Main": "c",
                                     "Mutex 4": "d",
                                     "MUTEX": "e",
                                     "Mutex Grabber": "f",
                                     "Mutex Per": "g"
                                 }, "unrecom", "mutex"),
                                 ({
                                     'Reg Key': 'a',
                                     'StartupName': 'a',
                                     'Active X Key': 'a',
                                     'ActiveX Key': 'a',
                                     'Active X Startup': 'a',
                                     'Registry Key': 'a',
                                     'Startup Key': 'a',
                                     'REG Key HKLM': 'a',
                                     'REG Key HKCU': 'a',
                                     'HKLM Value': 'a',
                                     'RegistryKey': 'a',
                                     'HKCUKey': 'a',
                                     'HKCU Key': 'a',
                                     'Registry Value': 'a',
                                     'keyClase': 'a',
                                     'regname': 'a',
                                     'registryname': 'a',
                                     'Custom Reg Key': 'a',
                                     'Custom Reg Name': 'a',
                                     'Custom Reg Value': 'a',
                                     'HKCU': 'a',
                                     'HKLM': 'a',
                                     'RegKey1': 'a',
                                     'RegKey2': 'a',
                                     'Reg Value': 'a'
                                  }, "unrecom", "registrypath"),
                             ]
                             )
    def test_ta_mapping(output, scriptname, mwcp_key):
        from cli import ta_mapping, register
        correct_reporter = add_metadata(output, mwcp_key)
        test_reporter = register()
        ta_mapping(output, scriptname)
        assert check_reporter_equality(test_reporter, correct_reporter)

    @staticmethod
    @pytest.mark.parametrize("output,keys_of_interest",
                             [
                                 ({}, []),
                                 ({"a": "b"}, ["a"]),
                                 ({"a": "b"}, ["b"]),
                             ]
                             )
    def test_refine_data(output, keys_of_interest):
        from cli import refine_data
        correct_data = {val: output[val] for val in keys_of_interest if val in output}
        test_data = refine_data(output, keys_of_interest)
        assert correct_data == test_data


    @staticmethod
    @pytest.mark.parametrize("data, mwcp_key",
                             [
                                 ({}, None),
                                 ({"address": "b"}, "address")
                             ]
                             )
    def test_map_fields(data, mwcp_key):
        from cli import map_fields, register
        correct_reporter = add_metadata(data, mwcp_key)
        test_reporter = register()
        map_fields(data, mwcp_key)
        assert test_reporter.as_dict() == correct_reporter.as_dict()


    @staticmethod
    @pytest.mark.parametrize("data",
                             [
                                 {},
                                 {"FTP UserName": "a", "FTP Password": "b"},
                                 {"FTPUserName": "a", "FTPPassword": "b"},
                                 {"FTPUSER": "a", "FTPPASS": "b"},
                                 {"FTPPASS": "a"},
                                 {"FTPUSER": "a"},
                                 {"Password": "a"},
                                 {"password": "a"}
                             ]
                             )
    def test_map_username_password_fields(data):
        from cli import map_username_password_fields, USERNAME_LIST, PASSWORD_LIST, PASSWORD_ONLY_LIST, register
        correct_reporter = get_reporter()
        for username, password in zip(USERNAME_LIST, PASSWORD_LIST):
            if username in data and password in data:
                correct_reporter.add_metadata('credential', [data[username], data[password]])
            elif password in data:
                correct_reporter.add_metadata('password', data[password])
            elif username in data:
                correct_reporter.add_metadata('username', data[username])
        only_password_data = {val: data[val] for val in PASSWORD_ONLY_LIST if val in data}
        correct_reporter = add_metadata(only_password_data, "password", correct_reporter)

        test_reporter = register()
        map_username_password_fields(data)
        assert test_reporter.as_dict() == correct_reporter.as_dict()

    @staticmethod
    @pytest.mark.parametrize("scriptname,data",
                             [
                                 ("NotIgnored", {"Install Path": "a", "Install Name": "b"}),
                                 ("NotIgnored", {"Install Path": "a"}),
                                 ("NotIgnored", {"Install Name": "a"}),
                                 ("NotIgnored", {}),
                                 ("Pandora", {"Install Path": "a"}),
                                 ("Pandora", {"Install Name": "a"}),
                                 ("Punisher", {"Install Path": "a", "Install Name": "b"}),
                                 ("Punisher", {})
                             ]
                             )
    def test_map_filepath_fields(scriptname, data):
        from cli import map_filepath_fields, FILEPATH_CONCATENATE_PAIR_LIST, register
        IGNORE_SCRIPT_LIST = ['Pandora', 'Punisher']

        correct_reporter = get_reporter()
        for pname, fname in FILEPATH_CONCATENATE_PAIR_LIST.items():
            if scriptname not in IGNORE_SCRIPT_LIST:
                if pname in data:
                    if fname in data:
                        correct_reporter.add_metadata(
                            "filepath", data[pname].rstrip("\\") + "\\" + data[fname])
                    else:
                        correct_reporter.add_metadata('directory', data[pname])
                elif fname in data:
                    correct_reporter.add_metadata('filename', data[fname])
            else:
                if pname in data:
                    correct_reporter.add_metadata('directory', data[pname])
                if fname in data:
                    correct_reporter.add_metadata('filename', data[fname])

        test_reporter = register()
        map_filepath_fields(scriptname, data)
        assert test_reporter.as_dict() == correct_reporter.as_dict()

    @staticmethod
    @pytest.mark.parametrize("data",
                             [
                                 {},
                                 {
                                     "FTP Directory": "a",
                                     "FTP Address": "b",
                                     "FTP Server": "d",
                                     "FTPHost": "e",
                                     "FTPHOST": "f"
                                 },
                                 {
                                     "FTP Directory": "a",
                                     "FTP Server": "d",
                                     "FTPHost": "e",
                                     "FTPHOST": "f"
                                 },
                                 {"FTP Directory": "a"},
                                 {"FTP Address": "a"},
                                 {
                                     "FTP Server": "a",
                                     "FTP Folder": "b"
                                 }
                             ]
                             )
    def test_map_ftp_fields(data):
        from cli import map_ftp_fields, FTP_FIELD_PAIRS, register
        correct_reporter = get_reporter()
        SPECIAL_HANDLING_PAIRS = {'FTP Address': 'FTP Port'}
        for host, port in SPECIAL_HANDLING_PAIRS.items():
            ftpdirectory = ''
            if 'FTP Directory' in data:
                ftpdirectory = data['FTP Directory']
            mwcpkey = ''
            if host in data:
                ftpinfo = "ftp://" + data[host]
                mwcpkey = 'c2_url'
            if port in data:
                if mwcpkey:
                    ftpinfo += ':' + data[port]
                else:
                    ftpinfo = [data[port], 'tcp']
                    mwcpkey = 'port'
            if ftpdirectory:
                if mwcpkey == 'c2_url':
                    ftpinfo += '/' + ftpdirectory
                    correct_reporter.add_metadata(mwcpkey, ftpinfo)
                elif mwcpkey:
                    correct_reporter.add_metadata(mwcpkey, ftpinfo)
                    correct_reporter.add_metadata('directory', ftpdirectory)
                else:
                    correct_reporter.add_metadata('directory', ftpdirectory)
            elif mwcpkey:
                correct_reporter.add_metadata(mwcpkey, ftpinfo)

        for address, port in FTP_FIELD_PAIRS.items():
            if address in data:
                if port in data:
                    correct_reporter.add_metadata(
                        "c2_url", "ftp://" + data[address] + "/" + data[port])
                else:
                    correct_reporter.add_metadata("c2_url", "ftp://" + data[address])

        test_reporter = register()
        map_ftp_fields(data)
        assert test_reporter.as_dict() == correct_reporter.as_dict()


    @staticmethod
    @pytest.mark.parametrize("data",
                             [
                                 {},
                                 {
                                     "Domain": "a",
                                     "Domains": "two\\backslashes\\",
                                     "dns": "one_backslashes\\and|blah",
                                     "C2": "one_backslashes\\and*blah",
                                 },
                                 {
                                     "Domain": ":",
                                     "Domains": "a",
                                     "p1": "b",
                                     "p2": "c",
                                 },
                                 {
                                     "Domain": ":",
                                     "Domains": "a",
                                     "Port": "d",
                                     "Port1": "e",
                                     "Port2": "f",
                                 },
                                 {
                                     "Domain": "a",
                                     "Client Control Port": "g",
                                     "Client Transfer Port": "h",
                                 },
                                 {
                                     "C2": ["a"],
                                     "Client Control Port": "g",
                                     "Client Transfer Port": "h",
                                 },

                             ]
                             )
    def test_map_c2_domains(data):
        from cli import map_c2_domains, DOMAINS_LIST, register
        correct_reporter = get_reporter()
        for domain_key in DOMAINS_LIST:
            if domain_key in data:
                if data[domain_key].count('\\') < 2:
                    if '|' in data[domain_key]:
                        domain_list = data[domain_key].rstrip('|').split('|')
                    elif '*' in data[domain_key]:
                        domain_list = data[domain_key].rstrip('*').split('*')
                    else:
                        domain_list = [data[domain_key]]
                    for addport in domain_list:
                        if ":" in addport:
                            correct_reporter.add_metadata("address", f"{addport}")
                        elif 'p1' in data or 'p2' in data:
                            if 'p1' in data:
                                correct_reporter.add_metadata("address", f"{data[domain_key]}:{data['p1']}")
                            if 'p2' in data:
                                correct_reporter.add_metadata("address", f"{data[domain_key]}:{data['p2']}")
                        elif 'Port' in data or 'Port1' in data or 'Port2' in data:
                            if 'Port' in data:
                                # CyberGate has a separator character in the field
                                # remove it here
                                data['Port'] = data['Port'].rstrip('|').strip('|')
                                for port in data['Port']:
                                    correct_reporter.add_metadata("address", f"{addport}:{data['Port']}")
                            if 'Port1' in data:
                                correct_reporter.add_metadata("address", f"{addport}:{data['Port1']}")
                            if 'Port2' in data:
                                correct_reporter.add_metadata("address", f"{addport}:{data['Port2']}")
                        elif domain_key == 'Domain' and (
                                "Client Control Port" in data or "Client Transfer Port" in data):
                            if "Client Control Port" in data:
                                correct_reporter.add_metadata("address",
                                                              f"{data['Domain']}:{data['Client Control Port']}")
                            if "Client Transfer Port" in data:
                                correct_reporter.add_metadata("address",
                                                              f"{data['Domain']}:{data['Client Transfer Port']}")
                        # Handle Mirai Case
                        elif domain_key == 'C2' and isinstance(data[domain_key], list):
                            for domain in data[domain_key]:
                                correct_reporter.add_metadata('address', domain)
                        else:
                            correct_reporter.add_metadata('address', addport)
        test_reporter = register()
        map_c2_domains(data)
        assert test_reporter.as_dict() == correct_reporter.as_dict()

    @staticmethod
    @pytest.mark.parametrize("data",
                             [
                                 {},
                                 {
                                     "Domain1": ":0",
                                     "Domain2": "a:b",
                                     "Domain3": "not_in_special_handling_list",
                                 },
                                 {
                                     "Domain1": "a",
                                     "Domain2": "b",
                                     "Port": "c",
                                     "Port2": "d",
                                 },
                                 {
                                     "Domain1": "a",
                                     "Port1": "b",
                                 },
                                 {
                                     "Domain1": "a"
                                 }
                             ]
                             )
    def test_map_domainX_fields(data):
        from cli import map_domainX_fields, register
        correct_reporter = get_reporter()
        SPECIAL_HANDLING_LIST = ['Domain1', 'Domain2']
        for suffix in range(1, 21):
            suffix = str(suffix)
            field = 'Domain' + suffix
            if field in data:
                if data[field] != ':0':
                    if ':' in data[field]:
                        address, port = data[field].split(':')
                        correct_reporter.add_metadata('address', f"{address}:{port}")
                    else:
                        if field in SPECIAL_HANDLING_LIST:
                            if "Port" in data:
                                correct_reporter.add_metadata('address', f"{data[field]}:{data['Port']}")
                            elif "Port" + suffix in data:
                                # customization if this doesn't hold
                                correct_reporter.add_metadata('address', f"{data[field]}:{data['Port' + suffix]}")
                            else:
                                correct_reporter.add_metadata("address", data[field])
                        else:
                            correct_reporter.add_metadata('address', data[field])

        test_reporter = register()
        map_domainX_fields(data)
        assert test_reporter.as_dict() == correct_reporter.as_dict()

    @staticmethod
    @pytest.mark.parametrize("data",
                             [
                                 {},
                                 {
                                     "Mutex": "a",
                                     "mutex": "b",
                                     "Mutex Main": "c",
                                     "Mutex 4": "d",
                                     "MUTEX": "e",
                                     "Mutex Grabber": "f",
                                     "Mutex Per": "g"
                                 },
                                 {
                                     "Mutex": "false"
                                 },
                                 {
                                     "Mutex": "true"
                                 }
                             ]
                             )
    def test_map_mutex(data):
        from cli import map_mutex, MUTEX_LIST, register
        correct_reporter = get_reporter()

        SPECIAL_HANDLING = 'Mutex'
        for mutex_key in MUTEX_LIST:
            if mutex_key in data:
                if mutex_key != SPECIAL_HANDLING:
                    correct_reporter.add_metadata('mutex', data[mutex_key])
                else:
                    if data[mutex_key] != 'false' and data[mutex_key] != 'true':
                        correct_reporter.add_metadata('mutex', data[mutex_key])

        test_reporter = register()
        map_mutex(data)
        assert test_reporter.as_dict() == correct_reporter.as_dict()


    @staticmethod
    @pytest.mark.parametrize("data",
                             [
                                 {},
                                 {
                                     'Domain': 'a',
                                     'Reg Key': 'a',
                                     'StartupName': 'a',
                                     'Active X Key': 'a',
                                     'ActiveX Key': 'a',
                                     'Active X Startup': 'a',
                                     'Registry Key': 'a',
                                     'Startup Key': 'a',
                                     'REG Key HKLM': 'a',
                                     'REG Key HKCU': 'a',
                                     'HKLM Value': 'a',
                                     'RegistryKey': 'a',
                                     'HKCUKey': 'a',
                                     'HKCU Key': 'a',
                                     'Registry Value': 'a',
                                     'keyClase': 'a',
                                     'regname': 'a',
                                     'registryname': 'a',
                                     'Custom Reg Key': 'a',
                                     'Custom Reg Name': 'a',
                                     'Custom Reg Value': 'a',
                                     'HKCU': 'a',
                                     'HKLM': 'a',
                                     'RegKey1': 'a',
                                     'RegKey2': 'a',
                                     'Reg Value': 'a'
                                 },
                                 {
                                     "Domain": "\\backslashes"
                                 },
                                 {
                                     "Domain": ".period"
                                 },
                                 {
                                     "Domain": "localhost"
                                 },
                                 {
                                     "Domain": "localhost*"
                                 }
                             ]
                             )
    def test_map_registry(data):
        from cli import map_registry, check_for_backslashes, REGISTRYPATH_LIST, register
        correct_reporter = get_reporter()

        SPECIAL_HANDLING = 'Domain'
        for ta_key in REGISTRYPATH_LIST:
            if ta_key in data:
                if ta_key == SPECIAL_HANDLING:
                    check_for_backslashes(ta_key, 'registrypath', data, correct_reporter)
                else:
                    correct_reporter.add_metadata('registrypath', data[ta_key])

        test_reporter = register()
        map_registry(data)
        assert test_reporter.as_dict() == correct_reporter.as_dict()


    @staticmethod
    @pytest.mark.parametrize("data",
                             [
                                 {},
                                 {
                                     "jarfoldername": "a",
                                     "jarname": "b",
                                     "RetryInterval": "c"
                                 },
                                 {
                                     "jarname": "a",
                                     "extensionname": "b"
                                 }
                             ]
                             )
    def test_map_jar_fields(data):
        from cli import map_jar_fields, register
        correct_reporter = get_reporter()
        jarinfo = ''
        mwcpkey = ''
        if 'jarfoldername' in data:
            jarinfo = data['jarfoldername']
            mwcpkey = 'directory'
        if 'jarname' in data:
            # if a directory is added put in the \\
            if jarinfo:
                jarinfo += '\\' + data['jarname']
                mwcpkey = 'filepath'
            else:
                mwcpkey = 'filename'
                jarinfo = data['jarname']
            if 'extensionname' in data:
                jarinfo += '.' + data['extensionname']
        correct_reporter.add_metadata(mwcpkey, jarinfo)

        test_reporter = register()
        map_jar_fields(data)
        assert test_reporter.as_dict() == correct_reporter.as_dict()


    @staticmethod
    @pytest.mark.parametrize("file_path",
                             yield_sample_file_paths()
                             )
    # def test_run_ratdecoders(file_path):
    #     from cli import run_ratdecoders
    #     # correct_reporter = get_reporter()
    #     no_result = "[!] No RATDecoder or File is Packed"
    #     correct_result = {'Mirai': {'other': {'Comment': 'File could not be decrypted '}}}
    #
    #     test_reporter = get_reporter()
    #     test_result = run_ratdecoders(file_path, test_reporter)
    #     if file_path.endswith('c805d89c6d26e6080994257d549fd8fec2a894dd15310053b0b8078064a5754b'):
    #         assert no_result == test_result
    #     elif file_path.endswith('35a6da3379b6e543b7f8eb45f27f3fd227c03c2620c4c72d8630583d7da82bba'):
    #         assert correct_result == test_result

    @staticmethod
    def test_main():
        # NOTE: All the methods within this method has been covered in the tests above
        pass
