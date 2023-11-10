import os
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Dict

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
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._service = self.datastore.get_service_with_delta(SERVICE_NAME)
        self.source_locks: Dict[str, threading.Lock] = {
            _s.name: threading.Lock() for _s in self._service.update_config.sources
        }

    # A sanity check to make sure we do in fact have things to send to services
    def _inventory_check(self) -> bool:
        check_passed = False
        if not self._update_dir:
            return check_passed

        # Each directory within the update_dir should be named after the source
        all_sources = set([_s.name for _s in self._service.update_config.sources])
        existing_sources = set(os.listdir(self._update_dir))
        missing_sources = all_sources - existing_sources

        # The check has passed if at least one source exists
        check_passed = bool(all_sources.intersection(existing_sources))

        if missing_sources:
            # If sources are missing, then clear caching from Redis and trigger source updates
            for source in missing_sources:
                # Ensure there are no active updates going on before you re-trigger download of source
                state = self.update_data_hash.get(f"{source}.{SOURCE_STATUS_KEY}")
                if state and state.get("status") == "UPDATING":
                    continue
                self._current_source = source
                self.set_source_update_time(0)
            self.trigger_update()

        return check_passed

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
            # Limit search for requirements.txt to root of folder containing parsers
            venv_created = False
            if "requirements.txt" in os.listdir(dir):
                create_venv(dir)
                venv_created = True

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
                with self.source_locks[source_name]:
                    try:
                        if venv_created:
                            # Remove venv before transfer
                            self.push_status("UPDATING", "Removing venv before transfer...")
                            shutil.rmtree(os.path.join(dir, "venv"))

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
                            self.push_status("UPDATING", "Re-creating necessary venv in persistent space...")
                            create_venv(destination)
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
        for source, lock in self.source_locks.items():
            source_path = os.path.join(self.latest_updates_dir, source)
            if os.path.exists(source_path):
                with lock:
                    try:
                        shutil.copytree(
                            os.path.join(self.latest_updates_dir, source),
                            os.path.join(output_directory, source),
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
                _, new_time = tempfile.mkstemp(prefix="time_keeper_", dir=UPDATER_DIR)
                self.log.info("An update is available for download from the datastore")
                self.log.debug(f"{self.updater_type} update available since {epoch_to_iso(old_update_time) or ''}")

                output_dir = self.prepare_output_directory()
                self.serve_directory(output_dir, new_time, al_client)


if __name__ == "__main__":
    with CXUpdateServer(downloadable_signature_statuses=["DEPLOYED", "DISABLED"]) as server:
        server.serve_forever()
