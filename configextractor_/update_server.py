import os
import shutil
import subprocess
import sys
import tempfile

from assemblyline.common import forge
from assemblyline.common.classification import InvalidClassification
from assemblyline.common.isotime import epoch_to_iso
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.client import UpdaterALClient
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key, UPDATER_DIR, UI_SERVER

from configextractor.main import ConfigExtractor

Classification = forge.get_classification()


class CXUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, files_sha256, client, source_name, default_classification=Classification.UNRESTRICTED):
        def import_parsers(cx: ConfigExtractor):
            upload_list = list()
            parser_paths = cx.parsers.keys()
            self.log.debug(f"Importing following parsers: {parser_paths}")
            for parser_path in parser_paths:
                parser_details = cx.get_details(parser_path)
                if parser_details:
                    id = f"{parser_details['framework']}_{parser_details['name']}"
                    try:
                        classification = parser_details["classification"]
                        if classification:
                            # Classification found, validate against engine configuration
                            Classification.normalize_classification(classification)
                        else:
                            # No classification string extracted, use default
                            classification = default_classification
                    except InvalidClassification:
                        self.log.warning(f'{id}: Classification "{classification}" not recognized. Defaulting to {default_classification}..')
                        classification = default_classification

                    upload_list.append(
                        Signature(
                            dict(
                                classification=classification,
                                data=open(parser_path, "r").read(),
                                name=parser_details["name"],
                                signature_id=id,
                                source=source_name,
                                type="configextractor",
                                status="DEPLOYED",
                            )
                        ).as_primitives()
                    )
            return (
                client.signature.add_update_many(source_name, "configextractor", upload_list, dedup_name=False)
            )

        for dir, _ in files_sha256:
            # Remove cached duplicates
            dir = dir[:-1]
            self.log.info(dir)

            PYTHON_PACKAGE_EXCL = ['yara-python', 'maco', 'pefile']

            # Find any requirement files and pip install to a specific directory that will get transferred to services
            # Limit search for requirements.txt to root of folder containing parsers
            if "requirements.txt" in os.listdir(dir):
                # Install to temporary directory
                cmd = "pip,install,{pkg},-t,{pkg_dest},--disable-pip-version-check,--no-cache-dir,--upgrade"
                if os.environ.get('PIP_PROXY'):
                    # Proxy is required to package installation
                    cmd += f",--proxy,{os.environ['PIP_PROXY']}"
                with tempfile.TemporaryDirectory() as pkg_dest:
                    # Install each package separately
                    for pkg in sorted(open(os.path.join(dir, "requirements.txt")).read().split()):
                        self.log.info(f'Installing {pkg}')
                        proc = subprocess.run(cmd.format(pkg=pkg, pkg_dest=pkg_dest).split(','),
                                              capture_output=True)
                        self.log.debug(proc.stdout)
                        if proc.stderr and not any(p in proc.stderr.decode() for p in PYTHON_PACKAGE_EXCL):
                            if b'dependency conflicts' not in proc.stderr:
                                self.log.error(proc.stderr)

                    # Copy off into local packages and source-specific directory
                    source_packages_dest = os.path.join(self.latest_updates_dir, f"{source_name}_python_packages")
                    # Purge to ensure the latest versions of the packages required
                    # Also, remove instances of the old directory if it still exists
                    shutil.rmtree(source_packages_dest, ignore_errors=True)
                    shutil.rmtree(os.path.join(self.latest_updates_dir, 'python_packages'), ignore_errors=True)

                    shutil.copytree(pkg_dest, source_packages_dest)
                    shutil.copytree(pkg_dest, "/var/lib/assemblyline/.local/lib/python3.9/site-packages",
                                    dirs_exist_ok=True)

            cx = ConfigExtractor(parsers_dirs=[dir], logger=self.log)
            if cx.parsers:
                self.log.info(f"Found {len(cx.parsers)} parsers from {source_name}")
                resp = import_parsers(cx)
                self.log.info(f"Sucessfully added {resp['success']} parsers from source {source_name} to Assemblyline.")
                self.log.debug(resp)

                # Save a local copy of the directory that may potentially contain dependency libraries for the parsers
                try:
                    destination = os.path.join(self.latest_updates_dir, source_name)
                    # Removing old version of directory if exists
                    if os.path.exists(destination):
                        self.log.debug(f'Removing directory: {destination}')
                        shutil.rmtree(destination)
                    shutil.move(dir, destination)
                    self.log.debug(f"{dir} -> {destination}")
                except shutil.Error as e:
                    if "already exists" in str(e):
                        continue
                    raise e

                # Cleanup modules generated from source
                for parser_module in [module for module in sys.modules.keys()
                                      if module.startswith(os.path.split(dir)[1])]:
                    sys.modules.pop(parser_module)
            else:
                raise Exception('No parser(s) found! Review source and try again later.')

    def is_valid(self, file_path) -> bool:
        return os.path.isdir(file_path)

    def do_local_update(self) -> None:
        old_update_time = self.get_local_update_time()
        if not os.path.exists(UPDATER_DIR):
            os.makedirs(UPDATER_DIR)

        self.log.info("Setup service account.")
        username = self.ensure_service_account()
        self.log.info("Create temporary API key.")
        with temporary_api_key(self.datastore, username) as api_key:
            self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}")
            al_client = UpdaterALClient.get_client(UI_SERVER, apikey=(username, api_key), verify=False)

            # Check if new signatures have been added
            self.log.info("Check for new signatures.")
            if al_client.signature.update_available(since=epoch_to_iso(old_update_time) or "",
                                                    sig_type=self.updater_type)["update_available"]:
                _, time_keeper = tempfile.mkstemp(
                    prefix="time_keeper_", dir=UPDATER_DIR
                )
                self.log.info("An update is available for download from the datastore")
                self.log.debug(f"{self.updater_type} update available since {epoch_to_iso(old_update_time) or ''}")

                output_directory = self.prepare_output_directory()

                # Merge Python packages into output directory
                output_python_dir = os.path.join(output_directory, 'python_packages')
                [(shutil.copytree(os.path.join(output_directory, pkg_dir), output_python_dir, dirs_exist_ok=True),
                  shutil.rmtree(os.path.join(output_directory, pkg_dir)))
                 for pkg_dir in os.listdir(output_directory) if pkg_dir.endswith('_python_packages')]

                self.serve_directory(output_directory, time_keeper, al_client)


if __name__ == "__main__":
    with CXUpdateServer(downloadable_signature_statuses=['DEPLOYED', 'DISABLED']) as server:
        server.serve_forever()
