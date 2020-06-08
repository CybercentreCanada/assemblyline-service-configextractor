import yaml
import yara
import mwcp
import sys
import click
import os
user = os.getlogin()
parser_dir = "/home/"+user+"/workspace/mwcp_parsers/"
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
    # Compile yara rules from yaml, rules designed for malware
    stream = open(yara_yml, 'r')
    parser_entries = yaml.full_load(stream)
    parser_objs = {}
    for parser in parser_entries:
        rule_source_paths = parser_entries[parser]['selector']['yara_rule']
        for rule in rule_source_paths:
            if not os.path.isfile(rule):
                raise Exception("Rule ", rule, "does not exist")

        parser_types = parser_entries[parser]['parser']
        parsers = validate_parsers(parser_types)
        compiled_rules = []
        for rule_source_path in rule_source_paths:
            rule = yara.compile(filepath=rule_source_path)
            compiled_rules.append(rule)
        parser_objs[parser] = Parser(parser, parsers, compiled_rules)

    return parser_objs


def openyara(rule_path):
    # returns list of strings containing yara rule strings
    with open(rule_path, 'r') as f:
        contents = f.read()
        group = []
        split = contents.split('rule')
        for i in split:
            if i:
                group.append('rule' + i)
        return group


def init_tags(tags):
    # Compile yara rules from path indicated in yaml, rules run on tags

    stream = open(yara_yml, 'r')
    parser_entries = yaml.full_load(stream)
    parser_objs = {}
    for parser in parser_entries:
        rule_source_paths = parser_entries[parser]['selector']['tag']
        parser_types = parser_entries[parser]['parser']
        parsers = validate_parsers(parser_types)
        compiled_rules = []
        for rule_source_path in rule_source_paths:
            r=(yara.compile(rule_source_path, externals=tags))
            compiled_rules.append(r)
        parser_objs[parser] = Parser(parser, parsers, compiled_rules)
    return parser_objs


def cb(data):
    match = data['matches']
    if match:
        # run mwcp what is parser name?
        #print(data)
        pass


def run(parser_list, f_path):
    mwcp.register_entry_points()
    mwcp.register_parser_directory(parser_dir)
    reporter = mwcp.Reporter()
    #all parsers in this list already matched
    # all parsers to be run must be in yml file in parser_dir
    outputs={}
    for parser in parser_list:
        reporter.run_parser(parser, file_path=f_path)
        output = reporter.get_output_text()
        outputs[parser]=output
    return outputs

def deduplicate(file_pars, tag_pars, file_path):
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
                else:
                    # print("file match not found for ", pars, obj.name)
                    pass
    if tag_pars is not None:
        for pars, obj in tag_pars.items():
            for rule in obj.compiled_rules:
                matched_rule = rule.match(file_path, callback=cb)
                if matched_rule :
                    obj.match = True
                    super_parser_list.extend(obj.parser_list)
                else:
                    print("tag match not found for ", pars)
    super_parser_list = [i.lower().capitalize() for i in super_parser_list]
    super_parser_list = list(set(super_parser_list))
    return super_parser_list

def compile(f_path, tags=None):
    # returns dict of parser names with Parser objects containing  compiled rules
    if tags is not None:
         parser_objs_tags = init_tags(tags)
         parser_objs = init()
         return parser_objs, parser_objs_tags
    parser_objs = init()
    return parser_objs, None

def start(f_path, tags=None):
    if tags is not None:
        parser_objs_tags = init_tags(tags)
    parser_objects = init()
    run(parser_objects,  f_path)


@click.command()
@click.argument('file_path', type=click.Path(exists=True))
def main(file_path) -> None:
    """
    Runs Malware parsers based on
    output of yara rules defined at and tags from AV hits
    """
    # if running cli mode tags are not expected
    file_pars,tag_pars = compile(file_path)
    print(file_pars,tag_pars)
    parsers = deduplicate(file_pars,tag_pars, file_path)
    print(parsers)
    run(parsers, file_path)
    # for each parser entry check if match exists, if so run all parsers in parser_list for that entry
    # but can't run parsers until final list of parsers to run, from tag and file parsers is finished


if __name__ == "__main__":
    main()
