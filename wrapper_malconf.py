import os
import sys
import json
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
RAT_DECODERS_PATH = os.path.join(ROOT_DIR, "RATDecoders")
sys.path.insert(0, RAT_DECODERS_PATH)
from malwareconfig import fileparser
from malwareconfig.modules import __decoders__, __preprocessors__


def preprocess(file_path):
    # Open and parse the file
    print("[+] Loading File: {0}".format(file_path))
    file_info = fileparser.FileParser(file_path=file_path)
    print("  [-] Found: {0}".format(file_info.malware_name))
    # First we preprocesss
    # Check for a packer we can unpack
    if file_info.malware_name in __preprocessors__:
        print("  [+] Running PreProcessor {0}".format(file_info.malware_name))
        module = __preprocessors__[file_info.malware_name]['obj']()
        module.set_file(file_info)
        module.pre_process()

    return file_info


def process_file(file_info):
    if file_info.malware_name in __decoders__:
        print("  [-] Running Decoder")
        module = __decoders__[file_info.malware_name]['obj']()
        module.set_file(file_info)
        module.get_config()
        conf = module.config
        print("  [-] Config Output\n")
        json_config = json.dumps(conf, indent=4, sort_keys=True)
        print(json_config)
        return conf
    else:

        return "[!] No RATDecoder or File is Packed"


def list_decoders():
    print("[+] Listing Decoders")
    for name in __decoders__.keys():
        print("  [-] Loaded: {0}".format(name))

    print("[+] Listing PreProcessors")
    for name in __preprocessors__.keys():
        print("  [-] Loaded: {0}".format(name))
    sys.exit()


def check_file(f_path=None):
    # We need at least one arg
    if f_path == None:
        print("[!] Not enough Arguments, Need at least file path\n")
        sys.exit()
    # Check for file or dir
    is_file = os.path.isfile(f_path)
    is_dir = os.path.isdir(f_path)
    if is_dir:
        print("[!] Path is directory not a file.\n")
        sys.exit()
    if not is_file:
        print("[!] You did not provide a valid file.\n")
        sys.exit()


if __name__ == "__main__":
    print("[+] RATDecoders Running")
    path = sys.argv[1]
    check_file(path)
    file = preprocess(path)
    output = process_file(file)
