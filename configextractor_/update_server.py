import os
import shutil
import subprocess
import tempfile
import time

from assemblyline.common import forge
from assemblyline.common.classification import InvalidClassification
from assemblyline.common.isotime import epoch_to_iso
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.client import get_client
from assemblyline_v4_service.updater.updater import (
    SERVICE_NAME,
    SOURCE_STATUS_KEY,
    UI_SERVER,
    UPDATER_DIR,
    ServiceUpdater,
    temporary_api_key,
)
from configextractor.main import ConfigExtractor

Classification = forge.get_classification()


def create_venv(dir):
    proc = subprocess.run(
        ["/opt/al_service/create_venv.sh", dir],
        cwd=dir,
        capture_output=True,
    )
    # Files used for debugging venv creation
    open(os.path.join(dir, "create_venv.out"), "wb").write(proc.stdout)
    if proc.stderr:
        open(os.path.join(dir, "create_venv.err"), "wb").write(proc.stderr)


class CXUpdateServer(ServiceUpdater):
    def import_update(
        self,
        files_sha256,
        client,
        source_name,
        default_classification=Classification.UNRESTRICTED,
    ):
        def import_parsers(cx: ConfigExtractor):
            upload_list = list()
            for parser_obj in cx.parsers.values():
                self.log.debug(f"Importing following parser: {parser_obj.module}")
                parser_details = cx.get_details(parser_obj)

                # Patch ID to prefix with the name of the source
                id = parser_obj.id
                id = ".".join([source_name] + id.split(".")[1:])

                if parser_details:
                    try:
                        classification = parser_details["classification"]
                        if classification:
                            # Classification found, validate against engine configuration
                            Classification.normalize_classification(classification)
                        else:
                            # No classification string extracted, use default
                            classification = default_classification
                    except InvalidClassification:
                        self.log.warning(
                            f'{id}: Classification "{classification}" not recognized. '
                            f"Defaulting to {default_classification}.."
                        )
                        classification = default_classification

                    upload_list.append(
                        Signature(
                            dict(
                                classification=classification,
                                data=open(parser_obj.module_path, "r").read(),
                                name=parser_details["name"],
                                signature_id=id,
                                source=source_name,
                                type="configextractor",
                                status="DEPLOYED",
                            )
                        ).as_primitives()
                    )
            return client.signature.add_update_many(source_name, "configextractor", upload_list, dedup_name=False)

        for dir, _ in files_sha256:
            # Remove cached duplicates
            dir = dir[:-1]
            self.log.info(dir)

            # Find any requirement files and pip install to a specific directory that will get transferred to services
            venv_created = []
            for root, _, files in os.walk(dir):
                if "requirements.txt" in files:
                    create_venv(root)
                    venv_created.append(root)

            cx = ConfigExtractor(parsers_dirs=[dir], logger=self.log)
            if cx.parsers:
                self.log.info(f"Found {len(cx.parsers)} parsers from {source_name}")
                resp = import_parsers(cx)
                self.push_status("UPDATING", "Parsers successfully stored as signatures in Signatures index.")
                self.log.info(f"Sucessfully added {resp['success']} parsers from source {source_name} to Assemblyline.")
                self.log.debug(resp)

                # Save a local copy of the directory that may potentially contain dependency libraries for the parsers
                self.log.info("Transferring directory to persistent storage")
                self.push_status("UPDATING", "Preparing to transfer parsers to local persistence...")
                try:
                    if venv_created:
                        # Remove venv before transfer
                        self.push_status("UPDATING", "Removing venv(s) before transfer...")
                        [shutil.rmtree(os.path.join(d, "venv")) for d in venv_created]

                    self.push_status("UPDATING", "Beginning transfer of parsers...")
                    destination = os.path.join(self.latest_updates_dir, source_name)
                    # Removing old version of directory if exists
                    if os.path.exists(destination):
                        self.log.info(f"Removing directory: {destination}")
                        shutil.rmtree(destination)
                        while os.path.exists(destination):
                            # Give some time for the OS to cleanup the directory
                            self.log.info("Sleeping..")
                            time.sleep(3)
                    shutil.move(dir, destination)
                    self.log.debug(f"{dir} → {destination}")
                    if venv_created:
                        self.push_status("UPDATING", "Re-creating necessary venv(s) in persistent space...")
                        [create_venv(d.replace(dir, destination)) for d in venv_created]
                except shutil.Error as e:
                    if "already exists" in str(e):
                        continue
                    raise e
            else:
                raise Exception("No parser(s) found! Review source and try again later.")
            self.log.info(f"Transfer of {source_name} completed")

    def is_valid(self, file_path) -> bool:
        return os.path.isdir(file_path)

    def prepare_output_directory(self) -> str:
        output_directory = tempfile.mkdtemp()
        for source in self._service.update_config.sources:
            if self.update_data_hash.get(f"{source.name}.{SOURCE_STATUS_KEY}")["state"] == "UPDATING":
                continue
            local_source_path = os.path.join(self.latest_updates_dir, source.name)
            if os.path.exists(local_source_path):
                try:
                    shutil.copytree(
                        local_source_path,
                        local_source_path.replace(self.latest_updates_dir, output_directory),
                        symlinks=True,
                        dirs_exist_ok=True,
                    )
                except shutil.Error:
                    pass
        return output_directory

    def do_local_update(self) -> None:
        old_update_time = self.get_local_update_time()
        if not os.path.exists(UPDATER_DIR):
            os.makedirs(UPDATER_DIR)

        self.log.info("Setup service account.")
        username = self.ensure_service_account()
        self.log.info("Create temporary API key.")
        with temporary_api_key(self.datastore, username) as api_key:
            self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}")
            al_client = get_client(
                UI_SERVER,
                apikey=(username, api_key),
                verify=False,
                datastore=self.datastore,
            )

            # Check if new signatures have been added
            self.log.info("Check for new signatures.")
            if al_client.signature.update_available(
                since=epoch_to_iso(old_update_time) or "", sig_type=self.updater_type
            )["update_available"]:
                # Create a temporary file for the time keeper
                new_time = tempfile.NamedTemporaryFile(prefix="time_keeper_", dir=UPDATER_DIR, delete=False)
                new_time.close()
                new_time = new_time.name
                self.log.info("An update is available for download from the datastore")
                self.log.debug(f"{self.updater_type} update available since {epoch_to_iso(old_update_time) or ''}")

                output_dir = self.prepare_output_directory()
                self.serve_directory(output_dir, new_time, al_client)


if __name__ == "__main__":
    with CXUpdateServer(downloadable_signature_statuses=["DEPLOYED", "DISABLED"]) as server:
        server.serve_forever()
