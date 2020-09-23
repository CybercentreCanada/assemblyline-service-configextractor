import yaml
import yara
import mwcp
import click
import os

import json
import wrapper_malconf as malconf
from six import iteritems
from pathlib import Path
from typing import List

parser_dir = "./mwcp_parsers/"
yara_yml = "./yara_parser.yaml"
parserconfig = "parser_config.yml"

DIRECTORY_LIST = ['Install Dir', 'InstallDir', 'InstallPath', 'Install Folder',
                  'Install Folder1', 'Install Folder2', 'Install Folder3',
                  'Folder Name', 'FolderName', 'pluginfoldername', 'nombreCarpeta']
DOMAINS_LIST = ['Domain', 'Domains', 'dns']
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


class Parser:
    def __init__(self, name, parser_list, compiled_rules, classification):
        self.name = name
        self.parser_list = parser_list
        self.compiled_rules = compiled_rules
        self.match = False
        self.classification = classification


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
                classification = parser_entries[parser]['classification']
                parsers = validate_parsers(parser_types)
                compiled_rules = []
                for rule_source_path in rule_source_paths:
                    rule = yara.compile(filepath=rule_source_path)
                    compiled_rules.append(rule)
                parser_objs[parser] = Parser(parser, parsers, compiled_rules, classification)
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
            classification = parser_entries[parser]['classification']
            parsers = validate_parsers(parser_types)
            if checkpaths(rule_source_paths):
                compiled_rules = []
                for rule_source_path in rule_source_paths:
                    r = (yara.compile(rule_source_path, externals=tags))
                    compiled_rules.append(r)
                parser_objs[parser] = Parser(parser, parsers, compiled_rules, classification)
    return parser_objs


def cb(data):
    match = data['matches']
    if match:
        pass


def validate_parser_config():
    yaml_parsers = {}
    # get list of .py files that don't start with _
    parsers = [p for p in Path(parser_dir).glob("[!_]*.py")]
    # find name of parser class
    for parser in parsers:
        file = open(parser_dir + parser.name)
        for line in file:
            if line.partition("class ")[2].partition("(Parser):")[0]:
                parser_class = line.partition("class ")[2].partition("(Parser):")[0]
                entry = {"description": f"{parser.stem} Parser", "author": "Not Found", "parsers": [f".{parser_class}"]}
                yaml_parsers[parser.stem] = entry
        file.close()
    path = parser_dir + parserconfig
    with open(path, "w+", encoding='utf-8') as f:
        for entry, value in yaml_parsers.items():
            p = {entry: value}
            document = yaml.dump(p, f)
    return [parser.name for parser in parsers]


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
        pass
    return outputs


def checkNames(parsers: List[str]):
    dir_parsers = [p[:-3] for p in os.listdir(parser_dir)]
    for parser in parsers:
        if parser.startswith("TA"):
            print("TA parser")
        elif parser not in dir_parsers:
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
    # add wildcard parsers
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


def register():
    mwcp.register_entry_points()
    mwcp.register_parser_directory(parser_dir)
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
                        addr, port = addport.split(":")
                        if addr and port:
                            reporter.add_metadata(
                                "c2_socketaddress", [addr, port, "tcp"])
                    elif 'p1' in data or 'p2' in data:
                        if 'p1' in data:
                            reporter.add_metadata("c2_socketaddress", [
                                data[domain_key], data['p1'], 'tcp'])
                        if 'p2' in data:
                            reporter.add_metadata("c2_socketaddress", [
                                data[domain_key], data['p2'], 'tcp'])
                    elif 'Port' in data or 'Port1' in data or 'Port2' in data:
                        if 'Port' in data:
                            # CyberGate has a separator character in the field
                            # remove it here
                            data['Port'] = data['Port'].rstrip('|').strip('|')
                            for port in data['Port']:
                                reporter.add_metadata("c2_socketaddress", [
                                    addport, data['Port'], 'tcp'])
                        if 'Port1' in data:
                            reporter.add_metadata("c2_socketaddress", [
                                addport, data['Port1'], 'tcp'])
                        if 'Port2' in data:
                            reporter.add_metadata("c2_socketaddress", [
                                addport, data['Port2'], 'tcp'])
                    elif domain_key == 'Domain' and ("Client Control Port" in data or "Client Transfer Port" in data):
                        if "Client Control Port" in data:
                            reporter.add_metadata("c2_socketaddress", [
                                data['Domain'], data['Client Control Port'], "tcp"])
                        if "Client Transfer Port" in data:
                            reporter.add_metadata("c2_socketaddress", [data['Domain'], data[
                                'Client Transfer Port'], "tcp"])
                    else:
                        reporter.add_metadata('c2_address', data[domain_key])


def map_domainX_fields(data, reporter):
    SUFFIX_LIST = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
                   '11', '12', '13', '14', '15', '16', '17', '18', '19', '20']
    SPECIAL_HANDLING_LIST = ['Domain1', 'Domain2']
    for suffix in SUFFIX_LIST:
        field = 'Domain' + suffix
        if field in data:
            if data[field] != ':0':
                if ':' in data[field]:
                    address, port = data[field].split(':')
                    reporter.add_metadata('c2_socketaddress', [
                        address, port, 'tcp'])
                else:
                    if field in SPECIAL_HANDLING_LIST:
                        if "Port" in data:
                            reporter.add_metadata("c2_socketaddress", [
                                data[field], data['Port'], "tcp"])
                        elif "Port" + suffix in data:
                            # assume tcp and c2--use per scriptname
                            # customization if this doesn't hold
                            reporter.add_metadata("c2_socketaddress", [
                                data[field], data['Port' + suffix], "tcp"])
                        else:
                            reporter.add_metadata("c2_address", data[field])
                    else:
                        reporter.add_metadata('c2_address', data[field])


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
