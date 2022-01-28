import os
import shutil
import yaml

from tempfile import TemporaryDirectory, TemporaryFile

from assemblyline_v4_service.updater.updater import ServiceUpdater


class ConfigXUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, files_sha256, client, source, default_classification) -> None:
        # Create a temporary directory to house the compiled final product
        with TemporaryDirectory() as compile_dir:

            # Master configuration of the consolidated dependencies
            master_yara_parser = dict()

            # Compile all dependencies together
            for file, _ in files_sha256:
                with TemporaryDirectory as temp_dep:
                    # Unpack each file
                    shutil.unpack_archive(file, extract_dir=temp_dep.name, format='tar')
                    # Analyze the yara_parser.yaml, look for duplications or potential 'toe-stepping' (ie. same name for a rule file)
                    yara_parser = yaml.safe_load(os.path.join(temp_dep.name, 'yara_parser.yaml'))
                    for name, config in yara_parser.values():
                        # If there is duplication at the file-level, we can rename the file and modify the configuration where used
                        # If there is duplication at the parser-level, we may need to rename the parser files and the configuration
                        # If classification is missing from a parser config, use the default_classification given by the source

                        # Once we're satisified, copy the potentially modified structure to our compile_dir directory (except yara_parser.yaml)

                        # Once we iterate over all dependencies, save the contents of yara_parser into yara_parser.yaml at the root

                        # Archive final product and make it accessible for do_local_update

    def is_valid(self, file_path) -> bool:
        # Make sure structure of unpacked archive matches expected directory structure
        # See: https://github.com/CybercentreCanada/configextractor-py

        # Validation of dependencies will revolve around testing if library can use the directory given on a sample
        with TemporaryDirectory() as temp_dep:
            shutil.unpack_archive(file_path, extract_dir=temp_dep.name, format='tar')
            test_run = os.subprocess.run(['cx', temp_dep.name, os.path.join(temp_dep.name, 'yara_parser.yaml')])
            if test_run.returncode:
                # If we get a non-zero response back, something must be wrong
                self.log.warning(f'Testing with {file_path} unsuccessful. Error: {test_run.stderr}')
                return False

        self.log.info(f'Testing with {file_path} successful!')
        return True


if __name__ == '__main__':
    with ConfigXUpdateServer(default_pattern=".*\/dependencies\/$") as server:
        server.serve_forever()
