import os
import shutil
import subprocess
import tempfile
import yaml

from collections import defaultdict

from assemblyline.common.isotime import now_as_iso
from assemblyline_v4_service.updater.updater import ServiceUpdater


UPDATER_DIR = os.getenv('UPDATER_DIR', os.path.join(tempfile.gettempdir(), 'updater'))
LATEST_UPDATES = os.path.join(UPDATER_DIR, 'latest_updates')

class ConfigXUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Create latest_updates directory if it doesn't already exist
        if not os.path.exists(LATEST_UPDATES):
            os.mkdir(LATEST_UPDATES)

        # Cleanup old timekeepers and archived files
        for item in os.listdir(UPDATER_DIR):
            if item.startswith("time_keeper_") | item.startswith("signatures_"):
                os.remove(item)

    def prepare_output_directory(self) -> str:
        def rename_key(name, keys):
            i = 1
            while f'{name}_{i}' in keys:
                i += 1
            return f'{name}_{i}'

        # Create a temporary directory to house the compiled final product
        compile_dir = tempfile.mkdtemp()

        # Master configuration of the consolidated dependencies
        master_yara_parser = dict()
        master_selectors = defaultdict(list)

        # Compile all dependencies together
        for folder in os.listdir(LATEST_UPDATES):
            # Analyze the yara_parser.yaml, look for duplications or potential 'toe-stepping' (ie. same name for a rule file)
            dependency = os.path.join(LATEST_UPDATES, folder)
            yara_parser = yaml.safe_load(open(os.path.join(dependency, 'yara_parser.yaml'), 'r').read())
            for name, config in yara_parser.items():
                if master_yara_parser.get(name):
                    # If there is duplication at the parser-level, we may need to rename the parser files and the configuration
                    orig_name = name
                    name = rename_key(name, master_yara_parser.keys())

                    # Replace the name used in the parser section
                    for k, v in config['parser']:
                        config['parser'][k] = [name if vv == orig_name else vv for vv in v]

                for selector_type in ['tag', 'yara_rule']:
                    for selector_file in config['selector'].get(selector_type, []):
                        if selector_file in master_selectors[selector_type]:
                            # If there is duplication at the file-level, rename the file and modify configuration
                            orig_file = selector_file
                            selector_file = rename_key(selector_file, master_selectors[selector_type])
                            os.rename(orig_file.replace('.', folder, 1), selector_file.replace('.', folder, 1))
                            config['selector'][selector_type] = selector_file

            master_yara_parser[name] = config

            # Once we're satisified, copy the potentially modified structure to our compile_dir directory
            shutil.copytree(dependency, compile_dir, dirs_exist_ok=True)

        # Once we iterate over all dependencies, save the contents of yara_parser into yara_parser.yaml at the root
        open(os.path.join(compile_dir, 'yara_parser.yaml'), 'w').write(yaml.dump(master_yara_parser))
        return compile_dir

    def import_update(self, files_sha256, client, source, default_classification) -> None:
        # Expecting one folder per source
        folder = files_sha256[0][0]
        yara_parser_path = os.path.join(folder, 'yara_parser.yaml')
        yara_parser = yaml.safe_load(open(yara_parser_path, 'r').read())
        for name, config in yara_parser.items():
            if not config.get('classification'):
                # If classification is missing from a parser config, use default_classification
                yara_parser[name]['classification'] = default_classification

        # Save modified contents back to disk
        open(yara_parser_path, 'w').write(yaml.dump(yara_parser))

        # Delete everything formerly downloaded by the source
        dest_dir = os.path.join(LATEST_UPDATES, source)
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)

        # Move to latest updates directory
        shutil.move(folder, dest_dir)

    def is_valid(self, file_path) -> bool:
        # Make sure structure of unpacked archive matches expected directory structure
        # See: https://github.com/CybercentreCanada/configextractor-py

        # Validation of dependencies will revolve around testing if library can use the directory given on a sample
        test_run = subprocess.run(['cx', file_path, os.path.join(file_path, 'yara_parser.yaml')])
        if test_run.returncode:
            # If we get a non-zero response back, something must be wrong
            self.log.warning(f'Testing with {file_path} unsuccessful. Error: {test_run.stderr}')
            return False

        self.log.info(f'Testing with {file_path} successful!')
        return True


if __name__ == '__main__':
    with ConfigXUpdateServer(default_pattern=".*\/dependencies\/$") as server:
        server.serve_forever()
