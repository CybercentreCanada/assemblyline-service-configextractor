import os
import shutil
import sys
import tarfile
import tempfile


from assemblyline.common import forge
from assemblyline.common.classification import InvalidClassification
from assemblyline.common.isotime import epoch_to_iso
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.updater import SOURCE_STATUS_KEY, UPDATER_DIR, ServiceUpdater
from configextractor.main import ConfigExtractor

Classification = forge.get_classification()


class CXUpdateServer(ServiceUpdater):
    def import_update(
        self,
        files_sha256,
        source_name,
        default_classification=Classification.UNRESTRICTED,
    ):
        extractors_found = False

        def import_parsers(cx: ConfigExtractor):
            upload_list = list()
            for parser_obj in cx.parsers.values():
                self.log.debug(f"Importing following parser: {parser_obj.module}")
                parser_details = cx.get_details(parser_obj)

                # Fetch ID of extractor for result-signature links
                id = parser_obj.id

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
                self.push_status("UPDATING", "Parsers successfully stored as signatures in Signatures index.")
                self.log.info(f"Sucessfully added {resp['success']} parsers from source {source_name} to Assemblyline.")
                self.log.debug(resp)

                # Save a local copy of the directory that may potentially contain dependency libraries for the parsers
                self.log.info("Transferring directory to persistent storage")
                self.push_status("UPDATING", "Preparing to transfer parsers to local persistence...")

                # Store updates as tar files
                destination = os.path.join(self.latest_updates_dir, source_name)
                if os.path.exists(destination):
                    if os.path.isfile(destination):
                        # Remove old update for source
                        os.remove(destination)
                    else:
                        # Legacy: remove directory
                        shutil.rmtree(destination)

                with tarfile.TarFile(destination, "x") as tar_file:
                    # Add to TAR file but maintain directory context when sending to service
                    tar_file.add(dir, f"/{os.path.basename(dir)}")
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
                if os.path.isfile(local_source_path):
                    # Extract contents of tarfile into output directory under source-named subdirectory
                    with tarfile.open(local_source_path, "r") as tar:
                        tar.extractall(local_source_path.replace(self.latest_updates_dir, output_directory))
                else:
                    # Maintain legacy support if what's available locally is a directory
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

        # Check if new signatures have been added
        self.log.info("Check for new signatures.")
        if self.client.signature.update_available(
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


if __name__ == "__main__":
    with CXUpdateServer(downloadable_signature_statuses=["DEPLOYED", "DISABLED"]) as server:
        server.serve_forever()
