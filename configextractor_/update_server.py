import os
import json
import shutil
import subprocess
import tempfile


from assemblyline.common import forge
from assemblyline.common.isotime import epoch_to_iso
from assemblyline.odm.models.signature import Signature
from assemblyline_client import get_client
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key, UPDATER_DIR, UI_SERVER

from configextractor.main import ConfigExtractor


classification = forge.get_classification()


class CXUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, files_sha256, client, source_name, default_classification=classification.UNRESTRICTED):
        def import_parsers(cx: ConfigExtractor):
            upload_list = list()
            parser_paths = cx.parsers.keys()
            self.log.debug(f"Importing following parsers: {parser_paths}")
            source_map = {}
            for parser_path in parser_paths:
                parser_details = cx.get_details(parser_path)
                if parser_details:
                    id = f"{parser_details['framework']}_{parser_details['name']}"
                    classification = parser_details["classification"] or default_classification
                    source_map[id] = dict(classification=classification, source_name=source_name)
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
                client.signature.add_update_many(source_name, "configextractor", upload_list, dedup_name=False),
                source_map,
            )

        for dir, _ in files_sha256:
            # Remove cached duplicates
            dir = dir[:-1]
            self.log.info(dir)

            # Find any requirement files and pip install to a specific directory that will get transferred to services
            for root, _, files in os.walk(dir):
                for file in files:
                    if file == "requirements.txt":
                        cmd = ["pip", "install", "-r", os.path.join(root, file),
                               "--disable-pip-version-check",
                               "--quiet",
                               "--upgrade",
                               ]

                        if os.environ.get('PIP_PROXY'):
                            # Proxy is required to package installation
                            cmd.extend(['--proxy', os.environ['PIP_PROXY']])
                        err = subprocess.run(cmd, capture_output=True).stderr
                        if err:
                            self.log.error(err)

                        shutil.copytree("/var/lib/assemblyline/.local/lib/python3.9/site-packages",
                                        os.path.join(self.latest_updates_dir, "python_packages"))

            cx = ConfigExtractor(parsers_dirs=[dir], logger=self.log)
            if cx.parsers:
                self.log.info(f"Found {len(cx.parsers)} parsers from {source_name}")
                resp, source_map = import_parsers(cx)
                self.log.info(f"Sucessfully added {resp['success']} parsers from source {source_name} to Assemblyline.")
                self.log.debug(resp)
                self.log.debug(source_map)

                # Save a local copy of the directory that may potentially contain dependency libraries for the parsers
                try:
                    destination = os.path.join(self.latest_updates_dir, source_name)
                    source_mapping_file = os.path.join(self.latest_updates_dir, "source_mapping.json")
                    # Removing old version of directory if exists
                    if os.path.exists(destination):
                        shutil.rmtree(destination)
                    shutil.move(dir, destination)
                    if os.path.exists(source_mapping_file):
                        _tmp = json.loads(open(source_mapping_file, "r").read())
                        _tmp.update(source_map)
                        source_map = _tmp

                    open(source_mapping_file, "w").write(json.dumps(source_map))
                except shutil.Error as e:
                    if "already exists" in str(e):
                        continue
                    raise e

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
            al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)

            # Check if new signatures have been added
            self.log.info("Check for new signatures.")
            if al_client.signature.update_available(since=epoch_to_iso(old_update_time) or "",
                                                    sig_type=self.updater_type)["update_available"]:
                _, time_keeper = tempfile.mkstemp(
                    prefix="time_keeper_", dir=UPDATER_DIR
                )
                self.log.info("An update is available for download from the datastore")
                self.log.debug(f"{self.updater_type} update available since {epoch_to_iso(old_update_time) or ''}")

                blocklisted_parsers = list()
                [blocklisted_parsers.extend(list(item.values())) for item in
                 al_client.search.signature(f"type:{self.updater_type} AND status:DISABLED", fl="id")["items"]]
                self.log.debug(f"Blocking the following parsers: {blocklisted_parsers}")
                output_directory = self.prepare_output_directory()
                open(os.path.join(output_directory, "blocked_parsers"), "w").write("\n".join(blocklisted_parsers))
                self.serve_directory(output_directory, time_keeper)


if __name__ == "__main__":
    with CXUpdateServer() as server:
        server.serve_forever()
