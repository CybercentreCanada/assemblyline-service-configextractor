import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time

from assemblyline.common import forge
from assemblyline.common.classification import InvalidClassification
from assemblyline.common.isotime import epoch_to_iso
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.client import get_client
from assemblyline_v4_service.updater.updater import (
    SIGNATURES_META_FILENAME,
    STATUS_FILE,
    UI_SERVER,
    UPDATER_DIR,
    ServiceUpdater,
    temporary_api_key,
)
from configextractor.main import ConfigExtractor

Classification = forge.get_classification()


class CXUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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
            if "requirements.txt" in os.listdir(dir):
                subprocess.run(
                    ["/opt/al_service/create_venv.sh", dir],
                    cwd=dir,
                    capture_output=True,
                )

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
                        self.log.debug(f"Removing directory: {destination}")
                        shutil.rmtree(destination)
                    shutil.move(dir, destination)
                    self.log.debug(f"{dir} -> {destination}")
                except shutil.Error as e:
                    if "already exists" in str(e):
                        continue
                    raise e
            else:
                raise Exception("No parser(s) found! Review source and try again later.")

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

                # Serve the live directory
                self.log.info("Update finished with new data.")
                new_tar = ""

                # Pull signature metadata from the API
                signature_map = {
                    item["signature_id"]: item
                    for item in al_client.search.stream.signature(
                        query=self.signatures_query,
                        fl="classification,source,status,signature_id,name",
                    )
                }

                open(os.path.join(self.latest_updates_dir, SIGNATURES_META_FILENAME), "w").write(
                    json.dumps(signature_map, indent=2)
                )

                try:
                    # Tar update directory
                    _, new_tar = tempfile.mkstemp(prefix="signatures_", dir=UPDATER_DIR, suffix=".tar.bz2")
                    tar_handle = tarfile.open(new_tar, "w:bz2")
                    tar_handle.add(self.latest_updates_dir, "/")
                    tar_handle.close()

                    # swap update directory with old one
                    self._update_dir = self.latest_updates_dir
                    self._update_tar, new_tar = new_tar, self._update_tar
                    self._time_keeper, new_time = new_time, self._time_keeper

                    # Write the new status file
                    temp_status = tempfile.NamedTemporaryFile("w+", delete=False, dir="/tmp")
                    json.dump(self.status(), temp_status.file)
                    os.rename(temp_status.name, STATUS_FILE)

                    self.log.info(
                        f"Now serving: {self._update_dir} and {self._update_tar} ({self.get_local_update_time()})"
                    )
                finally:
                    if new_tar and os.path.exists(new_tar):
                        self.log.info(f"Remove old tar file: {new_tar}")
                        time.sleep(3)
                        os.unlink(new_tar)
                    if new_time and os.path.exists(new_time):
                        self.log.info(f"Remove old time keeper file: {new_time}")
                        os.unlink(new_time)

                    # Cleanup old timekeepers/tars from unexpected termination(s) on persistent storage
                    for file in os.listdir(UPDATER_DIR):
                        file_path = os.path.join(UPDATER_DIR, file)
                        if (file.startswith("signatures_") and file_path != self._update_tar) or (
                            file.startswith("time_keeper_") and file_path != self._time_keeper
                        ):
                            try:
                                # Attempt to cleanup file from directory
                                os.unlink(file_path)
                            except FileNotFoundError:
                                # File has already been removed
                                pass


if __name__ == "__main__":
    with CXUpdateServer(downloadable_signature_statuses=["DEPLOYED", "DISABLED"]) as server:
        server.serve_forever()
