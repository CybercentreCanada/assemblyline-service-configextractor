import yaml
import yara
import mwcp
import click
import os
import json
from six import iteritems
from pathlib import Path
from typing import List, Dict

import wrapper_malconf as malconf

# Important file and directory paths
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
MWCP_PARSERS_DIR_PATH = os.path.join(ROOT_DIR, "mwcp_parsers")
YARA_PARSER_PATH = os.path.join(ROOT_DIR, "yara_parser.yaml")
MWCP_PARSER_CONFIG_PATH = os.path.join(MWCP_PARSERS_DIR_PATH, "parser_config.yml")

DIRECTORY_LIST = ['Install Dir', 'InstallDir', 'InstallPath', 'Install Folder',
                  'Install Folder1', 'Install Folder2', 'Install Folder3',
                  'Folder Name', 'FolderName', 'pluginfoldername', 'nombreCarpeta']
DOMAINS_LIST = ['Domain', 'Domains', 'dns', 'C2']
FILENAME_LIST = ['InstallName', 'Install Name', 'Exe Name',
                 'Jar Name', 'JarName', 'StartUp Name', 'File Name',
                 'USB Name', 'Log File', 'Install File Name']
FILEPATH_CONCATENATE_PAIR_LIST = {'Install Path': 'Install Name',
                                  'Install Directory': 'Install File Name'}
FTP_FIELD_PAIRS = {'FTP Server': 'FTP Folder',
                   'FTPHost': 'FTPPort', 'FTPHOST': 'FTPPORT'}
INJECTIONPROCESS_LIST = ['Process Injection', 'Injection', 'Inject Exe']
INTERVAL_LIST = ['FTP Interval', 'Remote Delay', 'RetryInterval']
MISSIONID_LIST = ['Campaign ID', 'CampaignID', 'Campaign Name',
                  'Campaign', 'ID', 'prefijo']
MUTEX_LIST = ['Mutex', 'mutex', 'Mutex Main', 'Mutex 4', 'MUTEX',
              'Mutex Grabber', 'Mutex Per']
NONC2_URL_LIST = ['Screen Rec Link', 'WebPanel', 'Plugins']
REGISTRYPATH_LIST = ['Domain', 'Reg Key', 'StartupName', 'Active X Key', 'ActiveX Key',
                     'Active X Startup', 'Registry Key', 'Startup Key', 'REG Key HKLM',
                     'REG Key HKCU', 'HKLM Value', 'RegistryKey', 'HKCUKey', 'HKCU Key',
                     'Registry Value', 'keyClase', 'regname', 'registryname',
                     'Custom Reg Key', 'Custom Reg Name', 'Custom Reg Value', 'HKCU',
                     'HKLM', 'RegKey1', 'RegKey2', 'Custom Reg Key', 'Reg Value']
VERSION_LIST = ['Version', 'version']
""" The following list is used when only a password is available, that is a password without
    a corresponding username. See username below if you have a username/password pair.
"""
PASSWORD_ONLY_LIST = ['Password', 'password']

""" Note: The username/password list are zipped together in pairs from the following
    two lists. There is a password only list above.
"""
USERNAME_LIST = ['FTP UserName', 'FTPUserName', 'FTPUSER']
PASSWORD_LIST = ['FTP Password', 'FTPPassword', 'FTPPASS']

SUPER_LIST = USERNAME_LIST + PASSWORD_LIST + PASSWORD_ONLY_LIST + VERSION_LIST + REGISTRYPATH_LIST + NONC2_URL_LIST + \
             MUTEX_LIST + MISSIONID_LIST + INTERVAL_LIST + INJECTIONPROCESS_LIST + \
             FILENAME_LIST + DOMAINS_LIST + DIRECTORY_LIST
FLCP = [item for pairs in FILEPATH_CONCATENATE_PAIR_LIST.items() for item in pairs]
FTPP = [item for pairs in FTP_FIELD_PAIRS.items() for item in pairs]
SUPER_LIST.extend(FTPP + FLCP)

MWCP_PARSER_PATHS = [p for p in Path(MWCP_PARSERS_DIR_PATH).glob("[!_]*.py")]


class Parser:
    def __init__(self, name: str, parser_list: List[str], compiled_rules: List[yara.Rules], classification: str,
                 malware: str, malware_types: List[str], mitre_group: str, mitre_att: str, category: str):
        self.name = name
        self.parser_list = parser_list
        self.compiled_rules = compiled_rules
        self.match = False
        self.classification = classification
        self.malware = malware
        self.malware_types = malware_types
        self.mitre_group = mitre_group
        self.mitre_att = mitre_att
        self.category = category

    def __eq__(self, other):
        # TODO: Find a way to compare equality between yara.Rules objects (compiled_rules)
        return self.name == other.name and self.parser_list == other.parser_list and \
               self.match == other.match and self.classification == other.classification and \
               self.malware == other.malware and self.malware_types == other.malware_types and \
               self.mitre_group == other.mitre_group and self.mitre_att == other.mitre_att and \
               self.category == other.category and self.run_on == other.run_on


class Entry:
    # Entry defined in yara_parser.yaml used internally
    def __init__(self, description: str, classification: str, category: str, mitre_group: str,
                 mitre_att: str, malware: str, run_on: str, yara_rules: List[str],
                 malware_types: List[str], parsers: List[dict], selector: dict,
                 tag_rules: List[str] = None):
        self.description = description
        self.classification = classification
        self.category = category
        self.mitre_group = mitre_group
        self.mitre_att = mitre_att
        self.malware = malware
        self.run_on = run_on
        self.yara_rules = yara_rules
        self.tag_rules = tag_rules
        self.malware_types = malware_types
        self.parsers = parsers
        self.selector = selector

# Loading up YARA Parsers
YARA_PARSERS_LOAD = yaml.full_load(open(YARA_PARSER_PATH, 'r'))
YARA_PARSERS = {}
for entry_name, dict_values in YARA_PARSERS_LOAD.items():
    if 'tag_rule' in dict_values['selector']:
        tag_rules = dict_values['selector']['tag_rule']
    else:
        tag_rules = None
    YARA_PARSERS[entry_name] = Entry(description=dict_values['description'],
                                     classification = dict_values['classification'],
                                     category = dict_values['category'],
                                     mitre_group = dict_values['mitre_group'],
                                     mitre_att = dict_values['mitre_att'],
                                     malware = dict_values['malware'],
                                     run_on = dict_values['run_on'],
                                     yara_rules = dict_values['selector']['yara_rule'],
                                     malware_types = dict_values['malware_type'],
                                     parsers = dict_values['parser'],
                                     tag_rules = tag_rules,
                                     selector = dict_values['selector'])

def validate_parsers(parser_list: List[dict]):
    mwcp_key = "MWCP"
    parsers_set = set()
    for parser in parser_list:
        if mwcp_key in parser:
            parsers_set.update(parser[mwcp_key])
        else:
            raise NameError(f"Parser type is invalid or unsupported, only {mwcp_key} supported")
    return list(parsers_set)


def check_paths(paths: List[str]):
    if paths:
        for path in paths:
            if not path:
                raise Exception("Path cannot be empty")
            abs_file_path = os.path.join(ROOT_DIR, path)
            if not os.path.isfile(abs_file_path):
                raise Exception("Rule ", abs_file_path, "does not exist")
        return True
    else:
        return False  # no path defined in yaml


def initialize_parser_objs(tags: dict = None):
    parser_objs = {}
    for parser_name in YARA_PARSERS:
        rule_source_paths = []
        # if tags are present then get tag rule paths
        yara_parser = YARA_PARSERS[parser_name]
        if tags:
            rule_source_paths = yara_parser.tag_rules
        else:
            rule_source_paths = yara_parser.yara_rules
        if not check_paths(rule_source_paths):
            continue
        validated_parsers = validate_parsers(yara_parser.parsers)
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
            classification=yara_parser.classification,
            malware=yara_parser.malware,
            malware_types=yara_parser.malware_types,
            mitre_group=yara_parser.mitre_group,
            mitre_att=yara_parser.mitre_att,
            category=yara_parser.category,
        )
    return parser_objs


def validate_parser_config():
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
    with open(MWCP_PARSER_CONFIG_PATH, "w+", encoding='utf-8') as f:
        for entry, value in yaml_parsers.items():
            parsers_in_config.append(entry)
            p = {entry: value}
            yaml.dump(p, f)

    if len(MWCP_PARSER_PATHS) != len(parsers_in_config):
        raise Exception("Number of parsers in mwcp_parsers and parser_config.yml don't match")


def run(parser_list: List[str], f_path: str, reporter):
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
        reporter.output_file(bytes(str(json.dumps(outputs)), encoding='utf-8'), "output.json")
    return outputs


def check_names(parsers: set):
    mwcp_parsers = set()
    for file in MWCP_PARSER_PATHS:
        mwcp_parsers.add(file.stem)
    diff = parsers - mwcp_parsers
    if diff:
        raise Exception(f"{diff} not found in {MWCP_PARSER_PATHS}")


def deduplicate(file_pars, tag_pars, file_path, tags_dict=None) -> List[str]:
    # for each entry we get all compiled file yara rules and see if theres a match,
    # if there is a match then we add all parsers for that parser object to the super list
    def is_match(file_path: str, parser_objects: Dict, tags_dict=None) -> Dict[str, List[yara.Rules]]:
        match_found = False
        matches = {}

        nonlocal super_parser_list
        if parser_objects is not None:
            for pars, obj in parser_objects.items():
                matched_rules = []
                for rule in obj.compiled_rules:
                    # each compiled rule object from yara_rule in yml
                    matched_rule = rule.match(file_path, externals=tags_dict)
                    if matched_rule:
                        matched_rules.extend(matched_rule)
                        super_parser_list.extend(obj.parser_list)
                matches[obj.malware] = matched_rules
        return matches

    # eliminate common parsers between yara tag match and yara file match so parsers aren't run twice
    super_parser_list = []
    and_malware = {}  # dict containing parsers to be run that are specified as AND (both file and tag rules need match)
    # add wildcard parsers that are run under all conditions
    for parser_name in YARA_PARSERS:
        yara_parser = YARA_PARSERS[parser_name]
        if 'wildcard' in yara_parser.selector:
            wildcard_parsers = validate_parsers(yara_parser.parsers)
            super_parser_list.extend(wildcard_parsers)
        if 'AND' in yara_parser.run_on:  # everything else is OR by default
            if 'tag' in yara_parser.selector and 'yara_rule' in yara_parser.selector:
                # then match must exist for some parser for both tag and file
                malware_name = yara_parser.malware
                and_malware[malware_name] = parser_name
            else:
                raise Exception("AND cannot be specified without both tag and file yara rules")

    is_match(file_path, file_pars)
    is_match(file_path, tag_pars, tags_dict)

    # run check to exclude and parsers

    def all_rules_match(compiled_rules):
        ctr = 0
        for rule in compiled_rules:
            match = rule.match(file_path, externals=tags_dict)
            if match:
                ctr = ctr + 1
        if len(compiled_rules) == ctr:
            return True
        else:
            return False

    # Provide AND/OR run functionality
    for malware, top_name in and_malware.items():
        file_yara_rules = file_pars[top_name].compiled_rules
        tag_yara_rules = tag_pars[top_name].compiled_rules
        file_bool = all_rules_match(file_yara_rules)
        tag_bool = all_rules_match(tag_yara_rules)
        if file_bool and tag_bool:
            print("both file and tag rules have match")
        else:
            print('tag or file rule did not match, excluding...')
            malware_to_parsers = file_pars[top_name].parser_list
            super_parser_list = [x for x in super_parser_list if x not in malware_to_parsers]

    super_parser_list = [i[0].upper() + i[1:] for i in super_parser_list]
    super_parser_list_set = set(super_parser_list)
    check_names(super_parser_list_set)
    super_parser_set_list = list(super_parser_list_set)
    return super_parser_set_list


def compile(tags=None):
    # returns dict of parser names with Parser objects containing  compiled rules
    if tags is not None:
        parser_objs_tags = initialize_parser_objs(tags)
        parser_objs = initialize_parser_objs()
        return parser_objs, parser_objs_tags
    parser_objs = initialize_parser_objs()
    return parser_objs, None


def register():
    mwcp.register_entry_points()
    mwcp.register_parser_directory(MWCP_PARSERS_DIR_PATH)
    reporter = mwcp.Reporter()
    return reporter


def check_for_backslashes(ta_key, mwcp_key, data, reporter):
    IGNORE_FIELD_LIST = ['localhost', 'localhost*']
    if '\\' in data[ta_key]:
        reporter.add_metadata(mwcp_key, data[ta_key])
    elif '.' not in data[ta_key] and data[ta_key] not in IGNORE_FIELD_LIST:
        reporter.add_metadata(mwcp_key, data[ta_key])


def ta_mapping(output, reporter, scriptname=""):
    # takes malwareconfig json output matches to mwcp fields found in reporter.metadata
    map_c2_domains(output, reporter)
    map_mutex(output, reporter)
    map_version(output, reporter)
    map_registry(output, reporter)
    map_domainX_fields(output, reporter)
    map_key_fields(output, reporter)
    map_missionid_fields(output, reporter)
    map_ftp_fields(output, reporter)
    map_network_fields(output, reporter)
    map_injectionprocess_fields(output, reporter)
    map_filepath_fields(scriptname, output, reporter)
    map_username_password_fields(output, reporter)
    map_interval_fields(output, reporter)
    map_filename_fields(output, reporter)
    map_network_fields(output, reporter)
    map_directory_fields(output, reporter)
    if scriptname == 'unrecom':
        map_jar_fields(output, reporter)


def map_fields(data, reporter, field_list, mwcp_key):
    for field in field_list:
        if data.get(field):
            reporter.add_metadata(mwcp_key, data[field])


def map_injectionprocess_fields(data, reporter):
    map_fields(data, reporter, INJECTIONPROCESS_LIST,
               'injectionprocess')


def map_networkgroup_nonc2_fields(data, reporter):
    map_fields(data, reporter, NONC2_URL_LIST, 'url')


def map_username_password_fields(data, reporter):
    for username, password in zip(USERNAME_LIST, PASSWORD_LIST):
        if username in data and password in data:
            reporter.add_metadata(
                'credential', [data[username], data[password]])
        elif password in data:
            reporter.add_metadata('password', data[password])
        elif username in data:
            reporter.add_metadata('username', data[username])

    map_fields(data, reporter, PASSWORD_ONLY_LIST, 'password')


def map_network_fields(data, reporter):
    map_networkgroup_nonc2_fields(data, reporter)


def map_filepath_fields(scriptname, data, reporter):
    IGNORE_SCRIPT_LIST = ['Pandora', 'Punisher']
    for pname, fname in iteritems(FILEPATH_CONCATENATE_PAIR_LIST):
        if scriptname not in IGNORE_SCRIPT_LIST:
            if pname in data:
                if fname in data:
                    reporter.add_metadata(
                        "filepath", data[pname].rstrip("\\") + "\\" + data[fname])
                else:
                    reporter.add_metadata('directory', data[pname])
            elif fname in data:
                reporter.add_metadata('filename', data[fname])
        else:
            if pname in data:
                reporter.add_metadata('directory', data[pname])
            if fname in data:
                reporter.add_metadata('filename', data[fname])


def map_ftp_fields(data, reporter):
    SPECIAL_HANDLING_PAIRS = {'FTP Address': 'FTP Port'}
    for host, port in iteritems(SPECIAL_HANDLING_PAIRS):
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
                reporter.add_metadata(mwcpkey, ftpinfo)
            elif mwcpkey:
                reporter.add_metadata(mwcpkey, ftpinfo)
                reporter.add_metadata('directory', ftpdirectory)
            else:
                reporter.add_metadata('directory', ftpdirectory)
        elif mwcpkey:
            reporter.add_metadata(mwcpkey, ftpinfo)

    for address, port in iteritems(FTP_FIELD_PAIRS):
        if address in data:
            if port in data:
                reporter.add_metadata(
                    "c2_url", "ftp://" + data[address] + "/" + data[port])
            else:
                reporter.add_metadata("c2_url", "ftp://" + data[address])


def map_directory_fields(data, reporter):
    map_fields(data, reporter, DIRECTORY_LIST, 'directory')


def map_filename_fields(data, reporter):
    map_fields(data, reporter, FILENAME_LIST, 'filename')


def map_c2_domains(data, reporter):
    for domain_key in DOMAINS_LIST:
        if domain_key in data:
            """ Hack here to handle a LuxNet case where a registry path is stored
                under the Domain key. """
            if data[domain_key].count('\\') < 2:
                if '|' in data[domain_key]:
                    """ The '|' is a separator character so strip it if
                        it is the last character so the split does not produce
                        an empty string i.e. '' """
                    domain_list = data[domain_key].rstrip('|').split('|')
                elif '*' in data[domain_key]:
                    """ The '*' is a separator character so strip it if
                        it is the last character """
                    domain_list = data[domain_key].rstrip('*').split('*')
                else:
                    domain_list = [data[domain_key]]
                for addport in domain_list:
                    if ":" in addport:
                        reporter.add_metadata("address", f"{addport}")
                    elif 'p1' in data or 'p2' in data:
                        if 'p1' in data:
                            reporter.add_metadata("address", f"{data[domain_key]}:{data['p1']}")
                        if 'p2' in data:
                            reporter.add_metadata("address", f"{data[domain_key]}:{data['p2']}")
                    elif 'Port' in data or 'Port1' in data or 'Port2' in data:
                        if 'Port' in data:
                            # CyberGate has a separator character in the field
                            # remove it here
                            data['Port'] = data['Port'].rstrip('|').strip('|')
                            for port in data['Port']:
                                reporter.add_metadata("address", f"{addport}:{data['Port']}")
                        if 'Port1' in data:
                            reporter.add_metadata("address", f"{addport}:{data['Port1']}")
                        if 'Port2' in data:
                            reporter.add_metadata("address", f"{addport}:{data['Port2']}")
                    elif domain_key == 'Domain' and ("Client Control Port" in data or "Client Transfer Port" in data):
                        if "Client Control Port" in data:
                            reporter.add_metadata("address", f"{data['Domain']}:{data['Client Control Port']}")
                        if "Client Transfer Port" in data:
                            reporter.add_metadata("address", f"{data['Domain']}:{data['Client Transfer Port']}")
                    # Handle Mirai Case
                    elif domain_key == 'C2' and isinstance(data[domain_key], list):
                        for domain in data[domain_key]:
                            reporter.add_metadata('address', domain)
                    else:
                        reporter.add_metadata('address', data[domain_key])


def map_domainX_fields(data, reporter):
    SPECIAL_HANDLING_LIST = ['Domain1', 'Domain2']
    for suffix in range(1, 21):
        suffix = str(suffix)
        field = 'Domain' + suffix
        if field in data:
            if data[field] != ':0':
                if ':' in data[field]:
                    address, port = data[field].split(':')
                    reporter.add_metadata('address', f"{address}:{port}")
                else:
                    if field in SPECIAL_HANDLING_LIST:
                        if "Port" in data:
                            reporter.add_metadata('address', f"{data[field]}:{data['Port']}")
                        elif "Port" + suffix in data:
                            # customization if this doesn't hold
                            reporter.add_metadata('address', f"{data[field]}:{data['Port' + suffix]}")
                        else:
                            reporter.add_metadata("address", data[field])
                    else:
                        reporter.add_metadata('address', data[field])


def map_mutex(data, reporter):
    SPECIAL_HANDLING = 'Mutex'
    for mutex_key in MUTEX_LIST:
        if mutex_key in data:
            if mutex_key != SPECIAL_HANDLING:
                reporter.add_metadata('mutex', data[mutex_key])
            else:
                if data[mutex_key] != 'false' and data[mutex_key] != 'true':
                    reporter.add_metadata('mutex', data[mutex_key])


def map_missionid_fields(data, reporter):
    map_fields(data, reporter, MISSIONID_LIST, 'missionid')


def map_version(data, reporter):
    map_fields(data, reporter, VERSION_LIST, 'version')


def map_registry(data, reporter):
    SPECIAL_HANDLING = 'Domain'
    for ta_key in REGISTRYPATH_LIST:
        if ta_key in data:
            if ta_key == SPECIAL_HANDLING:
                check_for_backslashes(ta_key, 'registrypath', data, reporter)
            else:
                reporter.add_metadata('registrypath', data[ta_key])


def map_interval_fields(data, reporter):
    map_fields(data, reporter, INTERVAL_LIST, 'interval')


def map_jar_fields(data, reporter):
    """This routine is for the unrecom family"""
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
    reporter.add_metadata(mwcpkey, jarinfo)


def map_key_fields(data, reporter):
    if "EncryptionKey" in data:
        reporter.add_metadata("key", data["EncryptionKey"])


def run_ratdecoders(file_path, reporter):
    file_info = malconf.preprocess(file_path)
    script_name = file_info.malware_name
    output = malconf.process_file(file_info, file_path)
    if type(output) is str:
        print(output)
        return output
    ta_mapping(output, reporter, script_name)
    others = {}

    for key in output:
        if key not in SUPER_LIST:
            others[key] = output[key]
    reporter.add_metadata("other", others)

    return {script_name: reporter.metadata}


@click.command()
@click.argument('file_path', type=click.Path(exists=True))
def main(file_path) -> None:
    """
    Runs Malware parsers based on
    output of yara rules defined at and tags from AV hits
    Required args
    file_path : relative or absolute path for file to be analyzed
    """
    # if running cli mode tags are not expected
    reporter = register()
    run_ratdecoders(file_path, reporter)
    validate_parser_config()
    file_pars, tag_pars = compile()
    parsers = deduplicate(file_pars, tag_pars, file_path)
    # for each parser entry check if match exists, if so run all parsers in parser_list for that entry
    run(parsers, file_path, reporter)
    reporter.print_report()

    # but can't run parsers until final list of parsers to run, from tag and file parsers is finished


if __name__ == "__main__":
    main()
