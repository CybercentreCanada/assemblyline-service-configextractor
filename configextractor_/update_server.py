import os
import shutil
import subprocess
import tempfile
import yaml

from collections import defaultdict

from assemblyline.common.isotime import now_as_iso
from assemblyline_v4_service.updater.updater import ServiceUpdater


UPDATER_DIR = os.getenv('UPDATER_DIR', os.path.join(tempfile.gettempdir(), 'updater'))


class ConfigXUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_local_update(self) -> None:
        try:
            # We're pulling in updates that aren't signatures from a persistent disk
            _, time_keeper = tempfile.mkstemp(prefix="time_keeper_", dir=UPDATER_DIR)
            output_directory = [os.path.join(UPDATER_DIR, dir)
                                for dir in os.listdir(UPDATER_DIR) if dir.startswith('offline_updates_')][0]

            if self._update_dir == output_directory:
                # Upgrade candidate is same as current, abort.
                raise ValueError

            self.serve_directory(output_directory, time_keeper)
        except (IndexError, ValueError):
            self.log.warning('No offline updates found.')
            os.unlink(time_keeper)

        # Cleanup duplicate time_keepers and archived files; only need to maintain one copy
        for root, _, files in os.walk(UPDATER_DIR):
            for file in files:
                fp = os.path.join(root, file)
                if fp not in [self._update_tar, self._time_keeper]:
                    os.unlink(fp)

    def import_update(self, files_sha256, client, source, default_classification) -> None:
        def rename_key(name, keys):
            i = 1
            while f'{name}_{i}' in keys:
                i += 1
            return f'{name}_{i}'

        # Create a temporary directory to house the compiled final product
        compile_dir = os.path.join(UPDATER_DIR, f'offline_updates_{now_as_iso()}')

        # Master configuration of the consolidated dependencies
        master_yara_parser = dict()
        master_selectors = defaultdict(list)

        # Compile all dependencies together
        for folder, _ in files_sha256:
            # Analyze the yara_parser.yaml, look for duplications or potential 'toe-stepping' (ie. same name for a rule file)
            yara_parser = yaml.safe_load(open(os.path.join(folder, 'yara_parser.yaml'), 'r').read())
            for name, config in yara_parser.items():
                if master_yara_parser.get(name):
                    # If there is duplication at the parser-level, we may need to rename the parser files and the configuration
                    orig_name = name
                    name = rename_key(name, master_yara_parser.keys())

                    # Replace the name used in the parser section
                    for k, v in config['parser']:
                        config['parser'][k] = [name if vv == orig_name else vv for vv in v]

                if not config.get('classification'):
                    # If classification is missing from a parser config, use default_classification
                    config['classification'] = default_classification

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
        shutil.copytree(folder, compile_dir)

        # Once we iterate over all dependencies, save the contents of yara_parser into yara_parser.yaml at the root
        open(os.path.join(compile_dir, 'yara_parser.yaml'), 'w').write(yaml.dump(master_yara_parser))

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
