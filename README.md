# ConfigExtractor Service

This Assemblyline service extracts malware configurations (such as IP, URL and domain) for various malware family by leveraging the [ConfigExtractor Python library](https://github.com/CybercentreCanada/configextractor-py) for analysis.

## Updater

### Sources

The updater for this service requires matches on directories containing parsers.

For example, the CAPE source will have a match pattern of `.*/modules/processing/parsers/CAPE/$` in which we're trying to target the parsers in this directory only.

### Persistence

The updater assumes that you have attached a storage volume to store your collection of sources. Contrary to other services, this updater relies on a storage volume to maintain persistence rather than Assemblyline's datastore.

### Python Packages

The updater is able to scan through the root directory containing parsers and look for a `requirements.txt` file and install Python packages to a directory that should get passed onto service instances.

If you require a proxy connection for package installation, add environment variable `PIP_PROXY` to the container configuration.

## [ConfigExtractor Python Library](https://github.com/CybercentreCanada/configextractor-py) (now available on [PyPI](https://pypi.org/project/configextractor-py/))

All parser directories that are able to work with this library should also be compatible with the service.

At the time of writing, we officially support the following frameworks:

- [MWCP](https://github.com/dod-cyber-crime-center/DC3-MWCP)
- [CAPE w/ MACO output](https://github.com/kevoreilly/CAPEv2)
- [MACO](https://github.com/CybercentreCanada/Maco)

# Contributions ✨

Thanks to everyone who have contributed to this project:

| Contributor                                                                                                                     | Contribution(s)                                                                                                                               |                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------: |
| <a href="https://github.com/jeFF0Falltrades"><img src="https://contrib.rocks/image?repo=jeFF0Falltrades/rat_king_parser" /></a> | Adding MACO compatibility to support integration of [rat_king_parser](https://github.com/jeFF0Falltrades/rat_king_parser) within Assemblyline | [![License](https://img.shields.io/github/license/jeFF0Falltrades/rat_king_parser)](https://github.com/jeFF0Falltrades/rat_king_parser/blob/master/LICENSE) |
