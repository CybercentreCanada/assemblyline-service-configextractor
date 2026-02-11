import json
import os
import shutil
import subprocess
import tempfile
import time

from assemblyline.common import forge
from assemblyline.common.isotime import DAY_IN_SECONDS, epoch_to_iso, now_as_iso
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.helper import SkipSource, filter_downloads, git_clone_repo, url_download
from assemblyline_v4_service.updater.updater import (
    SIGNATURES_META_FILENAME,
    SOURCE_STATUS_KEY,
    SOURCE_UPDATE_ATTEMPT_DELAY_BASE,
    SOURCE_UPDATE_ATTEMPT_MAX_RETRY,
    STATUS_FILE,
    UPDATER_DIR,
    ServiceUpdater,
)
from configextractor.main import ConfigExtractor

Classification = forge.get_classification()
IDENTIFY = forge.get_identify()
FILESTORE = forge.get_filestore()


class CXUpdateServer(ServiceUpdater):
    force_local_update = False

    def status(self):
        files_sha256 = {}

        # Generate a map to track changes to files in the update directory.
        # This allows the service to be more responsive to changes such as file updates or removals
        if self._update_dir and os.path.exists(self._update_dir):
            for file in os.listdir(self._update_dir):
                file_path = os.path.join(self._update_dir, file)
                sha256 = IDENTIFY.fileinfo(file_path, skip_fuzzy_hashes=True, calculate_entropy=False)["sha256"]
                # Store only filename as the key since the update directory is subject to change on each update
                files_sha256[file] = sha256

        return {
            "local_update_time": self.get_local_update_time(),
            "local_update_hash": self.get_local_update_hash(),
            "download_available": self._update_dir is not None,
            "_directory": self._update_dir,
            "_tar": self._update_tar,
            "_files": files_sha256,
        }

    def import_update(
        self,
        files_sha256,
        source_name,
        default_classification=Classification.UNRESTRICTED,
        configuration={},
        *args,
        **kwargs,
    ):
        extractors_found = False

        # If there is a configuration to set the deployment status of the extractor, map it out
        extractor_statuses = {
            extractor: status
            for status, extractor_list in configuration.get("deployment_status", {}).items()
            for extractor in extractor_list
        }

        def import_parsers(cx: ConfigExtractor):
            upload_list = list()
            for parser_obj in cx.parsers.values():
                self.log.debug(f"Importing following parser: {parser_obj.id}")
                parser_details = cx.get_details(parser_obj)

                # Fetch ID of extractor for result-signature links
                id = parser_obj.id

                if parser_details:
                    extractor_name = parser_details["name"]

                    # Set extractor deployment status based on source configuration, otherwise default to DEPLOYED
                    status = extractor_statuses.get(extractor_name, "DEPLOYED")

                    # Disable extractor without a YARA rule if configured to do so
                    if configuration.get("disable_yaraless_extractors") and not parser_obj.rule:
                        self.log.info(f"Disabling extractor because there's no YARA rule associated: {extractor_name}")
                        status = "DISABLED"

                    try:
                        # Normalize classification
                        classification = Classification.normalize_classification(parser_details.get("classification"))
                    except Exception:
                        # If the classification is invalid, fall back to default set by the source
                        classification = default_classification

                    upload_list.append(
                        Signature(
                            dict(
                                classification=classification,
                                data=open(parser_obj.module_path, "r").read(),
                                name=extractor_name,
                                signature_id=id,
                                source=source_name,
                                type="configextractor",
                                status=status,
                            )
                        ).as_primitives()
                    )
            return self.client.signature.add_update_many(source_name, "configextractor", upload_list, dedup_name=False)

        for dir, _ in files_sha256:
            # Remove cached duplicates
            dir = dir[:-1]
            self.log.info(dir)

            cx = ConfigExtractor(parsers_dirs=[dir], logger=self.log, create_venv=True)
            if cx.parsers:
                extractors_found = True
                self.log.info(f"Found {len(cx.parsers)} parsers from {source_name}")
                resp = import_parsers(cx)
                self.push_status(
                    "UPDATING",
                    "Parsers successfully stored as signatures in Signatures index.",
                )
                self.log.info(f"Sucessfully added {resp['success']} parsers from source {source_name} to Assemblyline.")
                self.log.debug(resp)

                # Save a local copy of the directory that may potentially contain dependency libraries for the parsers
                self.log.info("Transferring directory to persistent storage")
                self.push_status("UPDATING", "Preparing to transfer parsers to local persistence...")

                # Store updates as tar files
                destination = os.path.join(self.latest_updates_dir, source_name)
                old_hash = None
                if os.path.exists(destination):
                    old_hash = subprocess.check_output(["md5sum", destination], text=True).split()[0]
                    os.remove(destination)

                # Create a compressed TAR file with zstd compression for faster local extraction
                subprocess.run(
                    ["tar", "--zstd", "-cf", destination, "."],
                    capture_output=True,
                    cwd=dir,
                )

                if old_hash and old_hash != subprocess.check_output(["md5sum", destination], text=True).split()[0]:
                    self.force_local_update = True

                self.log.info(f"Transfer of {source_name} completed")
                return

        if not extractors_found:
            raise Exception("No parser(s) found! Review source and try again later.")

    def is_valid(self, file_path) -> bool:
        return os.path.isdir(file_path)

    def prepare_output_directory(self) -> str:
        output_directory = tempfile.mkdtemp()
        for source in self._service.update_config.sources:
            update_hash = self.update_data_hash.get(f"{source.name}.{SOURCE_STATUS_KEY}")
            if not update_hash or update_hash["state"] == "UPDATING":
                continue
            local_source_path = os.path.join(self.latest_updates_dir, source.name)
            if os.path.exists(local_source_path):
                # Save the contents of the update directory to the filestore for retrival via service-server
                output_source_dir = os.path.join(output_directory, source.name)
                shutil.copy(local_source_path, output_source_dir)
                file_data = IDENTIFY.fileinfo(output_source_dir)
                self.datastore.save_or_freshen_file(
                    file_data["sha256"],
                    file_data,
                    expiry=now_as_iso(
                        (source.update_interval or self._service.update_config.update_interval_seconds) + DAY_IN_SECONDS
                    ),
                    classification=source.default_classification,
                )
                with open(output_source_dir, "rb") as f:
                    FILESTORE.put(file_data["sha256"], f.read())
        return output_directory

    def do_local_update(self) -> None:
        old_update_time = self.get_local_update_time()
        if not os.path.exists(UPDATER_DIR):
            os.makedirs(UPDATER_DIR)

        # Check if any sources have been removed from Assemblyline
        sources = [s.name for s in self._service.update_config.sources]
        for file_tar in os.listdir(self.latest_updates_dir):
            if file_tar not in sources:
                # Source has been removed, cleanup stored entry
                self.log.info(f"{file_tar} looks like it was removed from the system. Forcing update..")
                os.remove(os.path.join(self.latest_updates_dir, file_tar))
                self.force_local_update = True

        # Check if new signatures have been added
        self.log.info("Check for new signatures.")
        if self.force_local_update or self.client.signature.update_available(
            since=epoch_to_iso(old_update_time) or "", sig_type=self.updater_type
        ):
            # Create a temporary file for the time keeper
            new_time = tempfile.NamedTemporaryFile(prefix="time_keeper_", dir=UPDATER_DIR, delete=False)
            new_time.close()
            new_time = new_time.name
            self.log.info("An update is available for download from the datastore")
            self.log.debug(f"{self.updater_type} update available since {epoch_to_iso(old_update_time) or ''}")

            output_dir = self.prepare_output_directory()
            self.serve_directory(output_dir, new_time)

        self.force_local_update = False

    def serve_directory(self, new_directory: str, new_time: str):
        self.log.info("Update finished with new data.")

        # Before serving directory, let's maintain a map of the different signatures and their current deployment state
        # This map allows the service to be more responsive to changes made locally to the system such as
        # classification changes.
        # This also avoids the need to have to insert this kind of metadata into the signature itself
        if self._service.update_config.generates_signatures:
            # Pull signature metadata from the API
            signature_map = {
                item["signature_id"]: item
                for item in self.datastore.signature.stream_search(
                    query=self.signatures_query, fl="classification,source,status,signature_id,name", as_obj=False
                )
            }
        else:
            # Pull source metadata from synced service configuration
            signature_map = {
                source.name: {"classification": source["default_classification"].value}
                for source in self._service.update_config.sources
            }

        with open(os.path.join(new_directory, SIGNATURES_META_FILENAME), "w") as meta_file:
            meta_file.write(json.dumps(signature_map, indent=2))

        try:
            # Tar update directory
            uuid = new_time.split("time_keeper_")[-1]
            new_tar = os.path.join(UPDATER_DIR, f"signatures_{uuid}.tar.zst")
            subprocess.run(["tar", "--zstd", "-cf", new_tar, "."], capture_output=True, cwd=new_directory)

            # swap update directory with old one
            self._update_dir, new_directory = new_directory, self._update_dir
            self._update_tar, new_tar = new_tar, self._update_tar
            self._time_keeper, new_time = new_time, self._time_keeper

            # Write the new status file
            temp_status = tempfile.NamedTemporaryFile("w+", delete=False, dir="/tmp")
            json.dump(self.status(), temp_status.file)
            os.rename(temp_status.name, STATUS_FILE)

            self.log.info(f"Now serving: {self._update_dir} and {self._update_tar} ({self.get_local_update_time()})")
        finally:
            if new_tar and os.path.exists(new_tar):
                self.log.info(f"Remove old tar file: {new_tar}")
                time.sleep(3)
                os.unlink(new_tar)
            if new_directory and os.path.exists(new_directory):
                self.log.info(f"Remove old directory: {new_directory}")
                shutil.rmtree(new_directory, ignore_errors=True)
            if new_time and os.path.exists(new_time):
                self.log.info(f"Remove old time keeper file: {new_time}")
                os.unlink(new_time)

            # Cleanup old timekeepers/tars from unexpected termination(s) on persistent storage
            for file in os.listdir(UPDATER_DIR):
                file_path = os.path.join(UPDATER_DIR, file)
                if (
                    (file.startswith("signatures_") and file_path != self._update_tar)
                    or (file.startswith("time_keeper_") and file_path != self._time_keeper)
                    or (file.startswith("update_dir_") and file_path != self._update_dir)
                ):
                    try:
                        # Attempt to cleanup file from directory
                        os.unlink(file_path)
                    except IsADirectoryError:
                        # Remove directory using
                        shutil.rmtree(file_path, ignore_errors=True)
                    except FileNotFoundError:
                        # File has already been removed
                        pass

    def do_source_update(self, service: Service) -> None:
        run_time = time.time()
        with tempfile.TemporaryDirectory() as update_dir:
            # Parse updater configuration
            previous_hashes: dict[str, dict[str, str]] = self.get_source_extra()
            sources: dict[str, UpdateSource] = {_s["name"]: _s for _s in service.update_config.sources}
            files_sha256: dict[str, dict[str, str]] = {}

            # Map already visited URIs to download paths (avoid re-cloning/re-downloads)
            seen_fetches = dict()

            # Go through each source queued and download file
            while self.update_queue.qsize():
                update_attempt = -1
                source_name = self.update_queue.get()

                if source_name not in sources:
                    # This source has been removed from the service configuration
                    continue

                while update_attempt < SOURCE_UPDATE_ATTEMPT_MAX_RETRY:
                    # Introduce an exponential delay between each attempt
                    time.sleep(SOURCE_UPDATE_ATTEMPT_DELAY_BASE**update_attempt)
                    update_attempt += 1

                    # Set current source for pushing state to UI
                    self._current_source = source_name
                    source_obj = sources[source_name]
                    old_update_time = self.get_source_update_time()

                    # Are we ignoring the cache for this source?
                    if source_obj.ignore_cache:
                        old_update_time = 0
                    try:
                        source = source_obj.as_primitives()
                        uri: str = source_obj.uri

                        # If source is not currently enabled/active, skip..
                        if not source_obj.enabled:
                            raise SkipSource

                        # Is it time for this source to run?
                        elapsed_time = time.time() - old_update_time
                        update_interval = source.get("update_interval") or service.update_config.update_interval_seconds
                        if elapsed_time < update_interval:
                            # Too early to run the update for this particular source, skip for now
                            raise SkipSource

                        self.push_status("UPDATING", "Starting..")
                        fetch_method = source.get("fetch_method", "GET")
                        default_classification = source.get("default_classification", Classification.UNRESTRICTED)

                        # Configure the client as necessary

                        # Enable syncing if the source specifies it
                        self.client.sync = source.get("sync", False)
                        # Override classfication of signatures if specified
                        # Reset client back to original classification state between updates
                        self.client.classification_override = None
                        if source.get("override_classification", False):
                            self.client.classification_override = default_classification

                        self.push_status("UPDATING", "Pulling..")
                        output = None
                        seen_fetch = seen_fetches.get(uri)
                        if seen_fetch == "skipped":
                            # Skip source if another source says nothing has changed
                            raise SkipSource
                        elif seen_fetch and os.path.exists(seen_fetch):
                            # We've already fetched something from the same URI, re-use downloaded path
                            self.log.info(f"Already visited {uri} in this run. Using cached download path..")
                            output = seen_fetches[uri]
                        else:
                            self.log.info(f"Fetching {source_name} using {fetch_method}")
                            # Pull sources from external locations
                            if uri.startswith("file:///"):
                                # Perform an update using a local mount
                                output = uri.split("file://", 1)[1]
                                if not os.path.exists(output):
                                    raise FileNotFoundError(f"{output} doesn't exist within container.")
                            elif fetch_method == "GIT" or uri.endswith(".git"):
                                # First we'll attempt by performing a Git clone
                                # (since not all services hint at being a repository in their URL),
                                output = git_clone_repo(source, old_update_time, self.log, update_dir)
                            else:
                                # Other fetch methods are meant for URL downloads using Requests
                                output = url_download(source, old_update_time, self.log, update_dir)
                            # Add output path to the list of seen fetches in this run
                            seen_fetches[uri] = output

                        files = filter_downloads(output, source["pattern"], self.default_pattern)

                        # Add to collection of sources for caching purposes
                        self.log.info(f"Found new {self.updater_type} rule files to process for {source_name}!")
                        validated_files = list()
                        for file, sha256 in files:
                            files_sha256.setdefault(source_name, {})
                            if previous_hashes.get(source_name, {}).get(file, None) != sha256 and self.is_valid(file):
                                files_sha256[source_name][file] = sha256
                                validated_files.append((file, sha256))

                        self.push_status("UPDATING", "Importing..")
                        # Import into Assemblyline
                        self.import_update(
                            validated_files, source_name, default_classification, source.get("configuration") or {}
                        )
                        self.push_status("DONE", "Signature(s) Imported.")
                    except SkipSource:
                        # This source hasn't changed, no need to re-import into Assemblyline
                        self.log.info(f"No new {self.updater_type} rule files to process for {source_name}")
                        if source_name in previous_hashes:
                            files_sha256[source_name] = previous_hashes[source_name]
                        seen_fetches[uri] = "skipped"
                        self.push_status("DONE", "Skipped.")

                        # Freshen the file that's stored in the database so it doesn't disappear on skip
                        file_info = IDENTIFY.fileinfo(os.path.join(self.latest_updates_dir, source_name))
                        self.datastore.save_or_freshen_file(
                            file_info["sha256"],
                            file_info,
                            expiry=now_as_iso(
                                source.get("update_interval", self._service.update_config.update_interval_seconds)
                                + DAY_IN_SECONDS
                            ),
                            classification=source.default_classification,
                        )
                        break
                    except Exception as e:
                        # There was an issue with this source, report and continue to the next
                        self.log.error(f"Problem with {source['name']}: {e}")
                        self.push_status("ERROR", str(e))
                        continue

                    self.set_source_update_time(run_time)
                    self.set_source_extra(files_sha256)
                    break
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == "__main__":
    with CXUpdateServer(downloadable_signature_statuses=["DEPLOYED", "NOISY", "DISABLED"]) as server:
        server.serve_forever()
