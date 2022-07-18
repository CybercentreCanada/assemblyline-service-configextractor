import os
import shutil
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
            for parser_path in parser_paths:
                parser_details = cx.get_details(parser_path)
                if parser_details:
                    upload_list.append(Signature(dict(
                        classification=parser_details['classification'] or default_classification,
                        data=open(parser_path, 'r').read(),
                        name=parser_details['name'],
                        signature_id=f"{parser_details['framework']}_{os.path.basename(parser_path)}",
                        source=source_name,
                        type='configextractor',
                        status="DEPLOYED",
                    )).as_primitives())
            return client.signature.add_update_many(source_name, 'configextractor', upload_list, dedup_name=False)

        for dir, _ in files_sha256:
            # Remove cached duplicates
            dir = dir[:-1]
            self.log.info(dir)
            cx = ConfigExtractor(parsers_dirs=[dir], logger=self.log, check_extension=True)
            resp = import_parsers(cx)
            self.log.info(f"Sucessfully added {resp['success']} parsers from source {source_name} to Assemblyline.")
            self.log.debug(resp)

            # Save a local copy of the directory that may potentially contain dependency libraries for the parsers
            try:
                shutil.move(dir, os.path.join(self.latest_updates_dir, source_name))
            except shutil.Error as e:
                if 'already exists' in str(e):
                    continue
                raise e

    def do_local_update(self) -> None:
        old_update_time = self.get_local_update_time()
        if not os.path.exists(UPDATER_DIR):
            os.makedirs(UPDATER_DIR)

        _, time_keeper = tempfile.mkstemp(prefix="time_keeper_", dir=UPDATER_DIR)
        self.log.info("Setup service account.")
        username = self.ensure_service_account()
        self.log.info("Create temporary API key.")
        with temporary_api_key(self.datastore, username) as api_key:
            self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}")
            al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)

            # Check if new signatures have been added
            self.log.info("Check for new signatures.")
            if al_client.signature.update_available(since=epoch_to_iso(old_update_time) or '',
                                                    sig_type=self.updater_type)['update_available']:
                self.log.info("An update is available for download from the datastore")
                self.log.debug(f"{self.updater_type} update available since {epoch_to_iso(old_update_time) or ''}")

                blocklisted_parsers = list()
                [blocklisted_parsers.extend(list(item.values()))
                    for item in al_client.search.signature(f'type:{self.updater_type} AND status:DISABLED',
                                                           fl='id')['items']]
                self.log.debug(f'Blocking the following parsers: {blocklisted_parsers}')
                output_directory = self.prepare_output_directory()
                open(os.path.join(output_directory, 'blocked_parsers'), 'w').write('\n'.join(blocklisted_parsers))
                self.serve_directory(output_directory, time_keeper)


if __name__ == '__main__':
    with CXUpdateServer() as server:
        server.serve_forever()
