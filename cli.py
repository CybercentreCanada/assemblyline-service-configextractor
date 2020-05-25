import yaml
import yara
import mwcp
import sys
import click
from collections import namedtuple

parser_dir = "/home/work/workspace/mwcp_parsers/"
yara_yml = "./yara_parser.yaml"


class Parser:
    def __init__(self, name, parser_list, compiled_rules):
        self.name = name
        self.parser_list = parser_list
        self.compiled_rules = compiled_rules
        self.match = False


def selector():
    '''selects whether to run parser
    based on yara rule, av tag or by default run all parsers
    if tag exists, run corresponding parser, if it doesn't then
    check if yara rules exist, if they do then run init, in
    other cases run all parsers defined in yara_yml'''


def validate_parsers(parser_list):
    parsers_dedup = []
    for i in parser_list:
        for key in i.keys():
            if key == 'MWCP':
                parsers_dedup.extend(i['MWCP'])
            elif key == 'CAPE':
                parsers_dedup.extend(i['CAPE'])
            else:
                raise NameError("Parser type is invalid, only CAPE and MWCP supported")

    parsers_dedup_list = list(set(parsers_dedup))
    return parsers_dedup_list


def init():
    # Initialize components needed to compile yara rules
    # Open yaml file to determine which parser to run
    stream = open(yara_yml, 'r')
    parser_entries = yaml.full_load(stream)
    parser_objs = {}
    for parser in parser_entries:
        rule_source_paths = parser_entries[parser]['selector']['yara_rule']
        parser_types = parser_entries[parser]['parser']
        parsers = validate_parsers(parser_types)
        compiled_rules = []
        for rule_source_path in rule_source_paths:
            # rule_source = openyara(rule_source_path, parser)
            rule = yara.compile(filepath=rule_source_path)
            compiled_rules.append(rule)
        parser_objs[parser] = Parser(parser, parsers, compiled_rules)
    return parser_objs


def openyara(rule_path, parser_name):
	#returns list of strings containing yara rule strings
    with open(rule_path, 'r') as f:
        contents = f.read()
        group = []
        split = contents.split('rule')
        for i in split:
            if i:
                group.append('rule' + i)

        return group


def init_tags(tags):
    # Initialize components needed to compile yara rules
    # Open yaml file to determine which parser to run
    stream = open(yara_yml, 'r')
    parser_entries = yaml.full_load(stream)
    parser_objs = {}
    for parser in parser_entries:
        rule_source_paths = parser_entries[parser]['selector']['tag']
        parser_types = parser_entries[parser]['parser']
        parsers = validate_parsers(parser_types)
        print(rule_source_paths,"\n\n", parsers)
        compiled_rules = []
        for rule_source_path in rule_source_paths:
            rule_sources = openyara(rule_source_path, parser)
            for rule in rule_sources:
            	print((rule))

            	r=(yara.compile(source=rule, externals=tags))
            	print("\n\n")
            rule = yara.compile(filepath=rule_source_path)
            print("\nrule is", rule)
            print('fdjsaa\n\nfdska')
            compiled_rules.append(rule)
        parser_objs[parser] = Parser(parser, parsers, compiled_rules)
    return parser_objs


def cb(data):
    match = data['matches']
    if not match:
        # run mwcp what is parser name?
        print(data)


def run(parser_dict, f_path):
    mwcp.register_entry_points()
    mwcp.register_parser_directory(parser_dir)
    reporter = mwcp.Reporter()
    # print(mwcp.get_parser_descriptions(config_only=False)) breaks idk why
    for parser, parser_obj in parser_dict.items():
        # check if match in any of compiled rules, if any match run all parsers
        print('parser is \n', parser)
        for rule in parser_obj.compiled_rules:
            match = rule.match(f_path)  # callback runs regardless of whether match to yara rule is found
            print("match is\n", match)
            if bool(match):  # if no match found match() returns empty dict, if callback runs then match returns empty dict as well
                print("\n\nparser list is",parser_obj.parser_list)
                for i in parser_obj.parser_list:
                    print(i, 'being run')
                    reporter.run_parser(i, file_path=f_path)
                    print(parser, "output:")
                    reporter.print_report()
        # all parsers to be run must be in yml file in parser_dir


def start(f_path, tags=None):
    print(sys.version)
    if tags is not None:
        #parser_objs_tags = init_tags(tags)
        print('ajajj')
    parser_objects = init()
    run(parser_objects, f_path)


@click.command()
@click.argument('file_path', type=click.Path(exists=True))
def main(file_path) -> None:
    """
    Runs Malware parsers based on
    output of yara rules defined at and tags from AV hits
    """
    start(file_path)


if __name__ == "__main__":
    main()
