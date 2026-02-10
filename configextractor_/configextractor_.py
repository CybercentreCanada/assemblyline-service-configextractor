import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from base64 import b64encode

import requests
from assemblyline.common import attack_map, forge
from assemblyline.odm.models.ontology.results import MalwareConfig
from assemblyline_v4_service.common.base import (
    MIN_SECONDS_BETWEEN_UPDATES,
    SERVICE_READY_PATH,
    SIGNATURES_META_FILENAME,
    UPDATES_CA,
    UPDATES_DIR,
    ServiceBase,
)
from assemblyline_v4_service.common.result import (
    BODY_FORMAT,
    Heuristic,
    Result,
    ResultSection,
    ResultTableSection,
    TableRow,
)
from configextractor.main import ConfigExtractor as CX
from maco.model import ConnUsageEnum, ExtractorModel

from configextractor_.maco_tags import (
    extract_connection_tags,
    extract_DNS_tags,
    extract_FTP_tags,
    extract_HTTP_tags,
    extract_proxy_tags,
    extract_SMTP_tags,
    extract_SSH_tags,
    tag_output,
)

cl_engine = forge.get_classification()

CONNECTION_USAGE = [k.name for k in ConnUsageEnum]
UPDATES_CHUNK_SIZE = int(os.environ.get("UPDATES_CHUNK_SIZE", "1024"))


class Base64TruncatedEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            ret = b64encode(o).decode()
            if len(ret) > 1000:
                ret = ret[:1000] + "..."
            return ret
        return json.JSONEncoder.default(self, o)


class Base64Encoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return b64encode(o).decode()
        return json.JSONEncoder.default(self, o)


class ConfigExtractor(ServiceBase):
    def __init__(self, config=None):
        super(ConfigExtractor, self).__init__(config)
        self.cx = None
        self.rules_file_sha256 = {}

    # Only relevant for services using updaters (reserving 'updates' as the defacto container name)
    # NOTE: This reimplementation is necessary to support zstd tarballs
    # which Python's tarfile module does not support natively in 3.11
    def _download_rules(self):
        # check if we just tried to download rules to reduce traffic
        if time.time() - self.update_check_time < MIN_SECONDS_BETWEEN_UPDATES:
            return
        self.update_check_time = time.time()

        # Resolve the update target
        scheme, verify = "http", None
        if os.path.exists(UPDATES_CA):
            scheme, verify = "https", UPDATES_CA
        url_base = f"{scheme}://{self.dependencies['updates']['host']}:{self.dependencies['updates']['port']}/"

        with requests.Session() as session:
            session.headers = {"x-apikey": self.dependencies["updates"]["key"]}
            session.verify = verify

            # Check if there are new signatures
            retries = 0
            while True:
                resp = session.get(url_base + "status")
                resp.raise_for_status()
                status = resp.json()
                if (
                    self.update_time is not None
                    and self.update_time >= status["local_update_time"]
                    and self.update_hash == status["local_update_hash"]
                ):
                    self.log.info(f"There are no new signatures. ({self.update_time} >= {status['local_update_time']})")
                    return
                if status["download_available"]:
                    self.log.info("A signature update is available, downloading new signatures...")
                    break
                self.log.warning("Waiting on update server availability...")
                time.sleep(min(5**retries, 30))
                retries += 1

            if os.path.exists(SERVICE_READY_PATH):
                # Mark the service as not ready while updating rules
                self.log.info("Service is marked as not ready while updating rules.")
                try:
                    os.remove(SERVICE_READY_PATH)
                except FileNotFoundError:
                    pass

                # Dedicated directory for updates
                if not os.path.exists(UPDATES_DIR):
                    os.mkdir(UPDATES_DIR)

            # Download the current update
            temp_directory = tempfile.mkdtemp(dir=UPDATES_DIR)

            old_rules_list = self.rules_list
            try:
                for file, sha256 in status["_files"].items():
                    dst_file_path = os.path.join(temp_directory, file)

                    if self.rules_file_sha256.get(file) != sha256:
                        self.log.info(f"File {file} has changed since the last update or is new...")

                        # Download the file into a buffer
                        buffer_handle, buffer_name = tempfile.mkstemp()
                        with os.fdopen(buffer_handle, "wb") as buffer:
                            resp = session.get(url_base + f"files/{file}", stream=True)
                            resp.raise_for_status()
                            for chunk in resp.iter_content(chunk_size=UPDATES_CHUNK_SIZE):
                                buffer.write(chunk)

                        if file == SIGNATURES_META_FILENAME:
                            # If the signatures meta file has changed, we can just move it over without unpacking
                            shutil.move(buffer_name, dst_file_path)
                        else:
                            if not os.path.exists(dst_file_path):
                                os.mkdir(dst_file_path)
                            # Unpack the file into the temp directory and move to updates directory
                            subprocess.check_output(["tar", "--zstd", "-xf", buffer_name, "-C", dst_file_path])

                        # Clean up the buffer
                        os.unlink(buffer_name)

                        # Update the sha256 for this file in the rules_file_sha256 map
                        self.rules_file_sha256[file] = sha256
                    elif os.path.exists(os.path.join(UPDATES_DIR, file)):
                        self.log.info(f"File {file} is unchanged since the last update, reusing existing file...")
                        shutil.copytree(os.path.join(UPDATES_DIR, file), dst_file_path)

                self.update_time = status["local_update_time"]
                self.update_hash = status["local_update_hash"]
                self.rules_directory, temp_directory = temp_directory, self.rules_directory
                # Try to load the rules into the service before declaring we're using these rules moving forward
                temp_hash = self._gen_rules_hash()
                self._clear_rules()
                self._load_rules()
                self.rules_hash = temp_hash
            except Exception as e:
                # Should something happen, we should revert to the old set and log the exception
                self.log.error(f"Error occurred while updating signatures: {e}. Reverting to the former signature set.")
                self.rules_directory, temp_directory = temp_directory, self.rules_directory
                # Clear rules that was added from the new set and reload old set
                self.rules_list = old_rules_list
                self._clear_rules()
                self._load_rules()
            finally:
                if temp_directory:
                    self.log.info(f"Removing temp directory: {temp_directory}")
                    shutil.rmtree(temp_directory, ignore_errors=True)

            with open(SERVICE_READY_PATH, "w"):
                # Mark the service as ready again
                self.log.info("Service is marked as ready after updating rules.")
                pass

    # Generate the rules_hash and init rules_list based on the raw files in the rules_directory from updater
    def _gen_rules_hash(self) -> str:
        self.rules_list = []
        signatures_meta_path = os.path.join(self.rules_directory, SIGNATURES_META_FILENAME)
        self.signatures_meta = json.loads(open(signatures_meta_path, "r").read())
        for obj in os.listdir(self.rules_directory):
            obj_path = os.path.join(self.rules_directory, obj)
            if obj_path != signatures_meta_path:
                self.rules_list.append(obj_path)
        all_sha256s = [f for f in self.rules_list]

        if len(all_sha256s) == 1:
            return all_sha256s[0][:7]

        return hashlib.sha256(" ".join(sorted(all_sha256s)).encode("utf-8")).hexdigest()[:7]

    def _load_rules(self) -> None:
        if self.rules_list:
            self.log.debug(self.rules_list)

            blocklist = [
                parser_name for parser_name, meta in self.signatures_meta.items() if meta["status"] == "DISABLED"
            ]
            self.log.info(f"Blocking the following parsers matching these patterns: {blocklist}")
            self.cx = CX(
                parsers_dirs=self.rules_list,
                logger=self.log,
                parser_blocklist=blocklist,
                create_venv=True,
                skip_install=True,
            )

        if not self.cx:
            raise Exception("Unable to start ConfigExtractor because can't find directory containing parsers")

        if not self.cx.parsers:
            raise Exception(
                f"Unable to start ConfigExtractor because can't find parsers in given directory: {self.rules_directory}"
            )

    def network_ioc_section(self, config, request, extra_tags, apply_heuristic) -> ResultSection:
        network_section = ResultSection("Network IOCs")

        network_fields = {
            "ftp": (ExtractorModel.FTP, extract_FTP_tags),
            "smtp": (ExtractorModel.SMTP, extract_SMTP_tags),
            "http": (ExtractorModel.Http, extract_HTTP_tags),
            "ssh": (ExtractorModel.SSH, extract_SSH_tags),
            "proxy": (ExtractorModel.Proxy, extract_proxy_tags),
            "dns": (ExtractorModel.DNS, extract_DNS_tags),
            "tcp": (ExtractorModel.Connection, extract_connection_tags),
            "udp": (ExtractorModel.Connection, extract_connection_tags),
        }
        request.temp_submission_data.setdefault("url_headers", {})
        for field, model_tuple in network_fields.items():
            sorted_network_config = {}
            for network_config in config.pop(field, []):
                if field == "http" and network_config.get("uri"):
                    headers = network_config.get("headers", {})
                    if network_config.get("user_agent"):
                        headers.update({"User-Agent": network_config["user_agent"]})
                    request.temp_submission_data["url_headers"].update({network_config["uri"]: headers})
                sorted_network_config.setdefault(network_config.get("usage", "other"), []).append(network_config)

            if sorted_network_config:
                connection_section = ResultSection(field.upper())
                for usage, connections in sorted_network_config.items():
                    model, tag_extractor = model_tuple
                    tags = tag_extractor(connections)
                    heuristic = Heuristic(2, signature=usage) if apply_heuristic else None
                    auto_collapse = False
                    if usage in ["decoy", "other"]:
                        # Display connections, but don't tag/score
                        tags, heuristic, auto_collapse = {}, None, True

                    # Propagate extra tags to section
                    tags.update(extra_tags)
                    table_section = ResultTableSection(
                        title_text=f"Usage: {usage.upper()} x{len(connections)}",
                        heuristic=heuristic,
                        tags=tags,
                        auto_collapse=auto_collapse,
                    )
                    for c in connections:
                        c.pop("usage", None)
                        table_section.add_row(TableRow(**model(**c).dict()))

                    if table_section.body:
                        connection_section.add_subsection(table_section)

                if connection_section.subsections:
                    network_section.add_subsection(connection_section)

        if network_section.subsections:
            return network_section

    def attach_ontology(self, config: dict):
        def strip_null(d: dict):
            clean_config = {}
            for k, v in d.items():
                if v:
                    if isinstance(v, dict):
                        clean_config[k] = strip_null(v)
                    elif isinstance(v, list):
                        if isinstance(v[0], dict):
                            clean_config[k] = [strip_null(vi) for vi in v]
                        elif isinstance(v[0], str):
                            # Remove empty strings
                            clean_config[k] = [vi for vi in v if vi]
                    else:
                        clean_config[k] = v
            return clean_config

        self.ontology.add_result_part(MalwareConfig, strip_null(config))

    def execute(self, request):
        result = Result()
        config_result = self.cx.run_parsers(
            request.file_path,
            # Give 30s of leeway for the service to finish processing
            timeout=self.service_attributes.timeout - 30,
        )
        if not config_result:
            request.result = result
            return

        a = tempfile.NamedTemporaryFile(delete=False)
        a.write(json.dumps(config_result, cls=Base64Encoder).encode())
        a.seek(0)
        request.add_supplementary(
            a.name,
            f"{request.sha256}_malware_config.json",
            "Raw output from configextractor-py",
        )
        for parser_framework, parser_results in config_result.items():
            for parser_output in parser_results:
                # Retrieve identifier from the results
                id = parser_output.pop("id", None)
                extractor_mod = self.cx.parsers[id]
                extractor_details = self.cx.get_details(extractor_mod)

                # For MACO >= 1.2.19, the `result_sharing` attribute should be used to classify the results
                if parser_framework == "MACO" and hasattr(extractor_mod, "result_sharing"):
                    classification = extractor_mod.result_sharing
                else:
                    # For other frameworks, use the general `classification` attribute
                    classification = extractor_details["classification"]

                if id not in self.signatures_meta:
                    self.log.warning(f"{id} wasn't found in signatures map. Skipping...")
                    continue

                # Get AL-specific details about the parser
                parser_name = extractor_details["name"]
                signature_meta = self.signatures_meta[id]
                if signature_meta["status"] == "DISABLED":
                    # Not processing output from this extractor
                    continue

                source_name = signature_meta["source"]
                config = parser_output.pop("config", {})

                # No configuration was extracted, likely due to an exception at runtime. Omit any tagging.
                if not config:
                    if request.get_param("include_empty_config"):
                        # Determine if empty configuration was intentional or because of exception
                        heuristic = Heuristic(
                            3,
                            signature=("exception" if parser_output.get("exception") else None),
                        )
                        if signature_meta["status"] == "NOISY":
                            # Don't raise missing configuration heuristic for noisy extractors
                            heuristic = None

                        # Append to result section but collapsed
                        ResultSection(
                            title_text=parser_name,
                            body=json.dumps(parser_output),
                            parent=result,
                            body_format=BODY_FORMAT.KEY_VALUE,
                            heuristic=heuristic,
                            classification=classification,
                            tags={"file.rule.configextractor": [f"{source_name}.{parser_name}"]},
                            auto_collapse=True,
                        )
                    continue

                # Patch output to be compatible with AL Ontology (which is modelled after the latest MACO release)

                # Correct revoked ATT&CK IDs
                for i, v in enumerate(config.get("attack", [])):
                    config["attack"][i] = attack_map.revoke_map.get(v, v)

                # Account for the possibility of 'family' field to be a string (Output of MACO <= 1.0.2)
                if isinstance(config["family"], str):
                    config["family"] = [config["family"]]

                for binary in config.get("binaries", []):
                    # Account for the possibility of 'encryption' field to be a dict (Output of MACO <= 1.0.10)
                    if binary.get("encryption") and isinstance(binary["encryption"], dict):
                        binary["encryption"] = [binary["encryption"]]

                # Include extractor's name for ontology output only
                config["config_extractor"] = config.get("config_extractor", f"{source_name}.{parser_name}")
                self.attach_ontology(config)
                config.pop("config_extractor")

                parser_output["family"] = config.pop("family")
                parser_output["Framework"] = parser_framework

                tags = {
                    "file.rule.configextractor": [f"{source_name}.{parser_name}"],
                    "attribution.family": [f for f in parser_output["family"]],
                    "attribution.implant": [f for f in parser_output["family"]],
                }
                attack_ids = config.pop("attack", [])
                for field in ["category", "version"]:
                    if config.get(field):
                        parser_output[field] = config.pop(field)

                if config.get("password"):
                    password = config.pop("password", [])
                    parser_output["password"] = password
                    tags.update({"info.password": password})

                if config.get("campaign_id"):
                    campaign_id = config.pop("campaign_id", [])
                    parser_output["Campaign ID"] = campaign_id
                    tags.update({"attribution.campaign": campaign_id})

                # Configuration extracted, create heuristic with all actionable tags
                apply_heuristic = signature_meta["status"] != "NOISY"
                parser_section = ResultSection(
                    title_text=parser_name,
                    body=json.dumps(parser_output),
                    parent=result,
                    body_format=BODY_FORMAT.KEY_VALUE,
                    tags=tags,
                    heuristic=Heuristic(1, attack_ids=attack_ids) if apply_heuristic else None,
                    classification=classification,
                )

                extra_tags = {"file.rule.configextractor": [f"{source_name}.{parser_name}"]}
                network_section = self.network_ioc_section(config, request, extra_tags, apply_heuristic)
                if network_section:
                    parser_section.add_subsection(network_section)

                for binary in config.get("binaries", []):
                    # Append binary data to submission for analysis
                    datatype = binary.get("datatype", "other")
                    data = binary.get("data")

                    if datatype in ["other", "payload"] and data:
                        if isinstance(data, str):
                            data = data.encode()
                        sha256 = hashlib.sha256(data).hexdigest()
                        a = tempfile.NamedTemporaryFile(delete=False)
                        a.write(data)
                        a.close()
                        request.add_extracted(
                            a.name,
                            f"binary_{datatype}_{sha256}",
                            "Extracted binary file",
                        )

                if config:
                    other_tags = {}
                    tag_output(config, other_tags)
                    ResultSection(
                        "Other data",
                        body=json.dumps(config, cls=Base64TruncatedEncoder),
                        body_format=BODY_FORMAT.JSON,
                        parent=parser_section,
                        tags=other_tags,
                    )

        request.result = result
