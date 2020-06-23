import yaml
import yara
import mwcp
import click
import os
import json
from typing import List

parser_dir = "./mwcp_parsers/"
yara_yml = "./yara_parser.yaml"
parserconfig = "parser_config.yml"


class Parser:
    def __init__(self, name, parser_list, compiled_rules):
        self.name = name
        self.parser_list = parser_list
        self.compiled_rules = compiled_rules
        self.match = False


def validate_parsers(parser_list):
    parsers_dedup = []
    for i in parser_list:
        for key in i.keys():
            if key == 'MWCP':
                parsers_dedup.extend(i['MWCP'])
            elif key == 'CAPE':
                pass
                # TODO add compatibility for cape parsers
                # parsers_dedup.extend(i['CAPE'])
            else:
                raise NameError("Parser type is invalid, only CAPE and MWCP supported")

    parsers_dedup_list = list(set(parsers_dedup))
    return parsers_dedup_list


def checkpaths(paths: List[str]):
    if paths:
        for path in paths:
            if not path:
                raise Exception("Path cannot be empty")
            if not os.path.isfile(path):
                raise Exception("Rule ", path, "does not exist")
        return True
    else:
        return False  # no path defined in yaml


def init():
    # Compile yara rules from yaml, rules designed for malware
    stream = open(yara_yml, 'r')
    parser_entries = yaml.full_load(stream)
    parser_objs = {}
    for parser in parser_entries:
        if 'yara_rule' in parser_entries[parser]['selector']:
            rule_source_paths = parser_entries[parser]['selector']['yara_rule']
            if checkpaths(rule_source_paths):
                parser_types = parser_entries[parser]['parser']
                parsers = validate_parsers(parser_types)
                compiled_rules = []
                for rule_source_path in rule_source_paths:
                    rule = yara.compile(filepath=rule_source_path)
                    compiled_rules.append(rule)
                parser_objs[parser] = Parser(parser, parsers, compiled_rules)
    return parser_objs


def init_tags(tags):
    # Compile yara rules from path indicated in yaml, rules run on tags

    stream = open(yara_yml, 'r')
    parser_entries = yaml.full_load(stream)
    parser_objs = {}
    for parser in parser_entries:
        if 'tag' in parser_entries[parser]['selector']:
            rule_source_paths = parser_entries[parser]['selector']['tag']
            parser_types = parser_entries[parser]['parser']
            parsers = validate_parsers(parser_types)
            if checkpaths(rule_source_paths):
                compiled_rules = []
                for rule_source_path in rule_source_paths:
                    r = (yara.compile(rule_source_path, externals=tags))
                    compiled_rules.append(r)
                parser_objs[parser] = Parser(parser, parsers, compiled_rules)
    return parser_objs


def cb(data):
    match = data['matches']
    if match:
        pass


def validate_parser_config():
    parsers = []
    yaml_parsers = {}

    for file in os.listdir(parser_dir):
        if file.endswith(".py"):
            parsers.append(file)
    parsers.remove("__init__.py")

    # find name of parser class
    for parser in parsers:
        file = open(parser_dir + parser)
        parser = parser[:-3]
        for line in file:
            if line.partition("class ")[2].partition("(Parser):")[0]:
                parser_class = line.partition("class ")[2].partition("(Parser):")[0]
                entry = {"description": f"{parser} Parser", "author": "Not Found", "parsers": [f".{parser_class}"]}
                yaml_parsers[parser] = entry
        file.close()
    path = parser_dir + parserconfig
    with open(path, "w+", encoding='utf-8') as f:
        for entry, value in yaml_parsers.items():
            p = {entry: value}
            document = yaml.dump(p, f)
    return [parser[:-3] for parser in parsers]


def run(parser_list: List[str], f_path: str):
    mwcp.register_entry_points()
    mwcp.register_parser_directory(parser_dir)
    reporter = mwcp.Reporter()
    # all parsers in this list already matched
    # all parsers to be run must be in yml file in parser_dir
    outputs = {}
    for parser in parser_list:
        reporter.run_parser(parser, file_path=f_path)
        output = reporter.get_output_text()
        if reporter.metadata:
            outputs[parser] = reporter.metadata
        if __name__ == '__main__':
            print(f"{parser}: \n", output)
    if __name__ == '__main__':
        reporter.output_file(bytes(str(json.dumps(outputs)), encoding='utf-8'),"output.json")
    return outputs
def checkNames(parsers: List[str]):
    dir_parsers=[p[:-3] for p in os.listdir(parser_dir)]
    for parser in parsers:
        if parser not in dir_parsers:
            raise Exception(f"{parser} not found in {parser_dir}")

def deduplicate(file_pars, tag_pars, file_path, tags_dict=None):
    # eliminate common parsers between yara tag match and yara file match so parsers aren't run twice
    # there needs to be a match first
    super_parser_list = []
    # foreach entry we get all compiled file yara rules and see if theres a match,
    # if there is a match then we add all parsers for that parser object to the super list
    if file_pars is not None:
        for pars, obj in file_pars.items():
            for rule in obj.compiled_rules:
                # each compiled rule object from yara_rule in yml
                matched_rule = rule.match(file_path, callback=cb)
                if matched_rule:
                    obj.match = True
                    super_parser_list.extend(obj.parser_list)
    if tag_pars is not None:
        for pars, obj in tag_pars.items():
            for rule in obj.compiled_rules:
                matched_rule = rule.match(file_path, callback=cb, externals=tags_dict)
                if matched_rule:
                    obj.match = True
                    super_parser_list.extend(obj.parser_list)
    # add wilcard parsers
    stream = open(yara_yml, 'r')
    parser_entries = yaml.full_load(stream)
    for parser in parser_entries:
        if 'wildcard' in parser_entries[parser]['selector']:
            wildcard_parsers = validate_parsers(parser_entries[parser]['parser'])
            super_parser_list.extend(wildcard_parsers)

    super_parser_list = [i[0].upper() + i[1:] for i in super_parser_list]
    super_parser_list = list(set(super_parser_list))
    checkNames(super_parser_list)

    return super_parser_list


def compile(tags=None):
    # returns dict of parser names with Parser objects containing  compiled rules
    if tags is not None:
        parser_objs_tags = init_tags(tags)
        parser_objs = init()
        return parser_objs, parser_objs_tags
    parser_objs = init()
    return parser_objs, None


@click.command()
@click.argument('file_path', type=click.Path(exists=True))
def main(file_path) -> None:
    """
    Runs Malware parsers based on
    output of yara rules defined at and tags from AV hits
    """
    # if running cli mode tags are not expected
    validate_parser_config()
    file_pars, tag_pars = compile()
    parsers = deduplicate(file_pars, tag_pars, file_path)
    # for each parser entry check if match exists, if so run all parsers in parser_list for that entry
    run(parsers, file_path)
    # but can't run parsers until final list of parsers to run, from tag and file parsers is finished


if __name__ == "__main__":
    main()
