# ConfigExtractor Service
This Assemblyline service extracts malware configurations (such as IP, URL and domain) for various malware family by leveraging the [ConfigExtractor Python library](https://github.com/CybercentreCanada/configextractor-py) for analysis.

## Updater

### Sources
The updater for this service requires matches on directories containing parsers.


For example, the CAPE source will have a match pattern of `.*/modules/processing/parsers/CAPE/$` in which we're trying to target the parsers in this directory only.

### Persistence
The updater assumes that you have attached a storage volume to store your collection of sources. Contrary to other services, this updater relies on a storage volume to maintain persistence rather than Assemblyline's datastore.

### Python Packages
The updater is able to scan through the directory containing parsers and look for `requirements.txt` files and install Python packages to a directory that should get passed onto service instances.

## [ConfigExtractor Python Library](https://github.com/CybercentreCanada/configextractor-py)

All parser directories that are able to work with this library should also be compatible with the service.

At the time of writing, we officially support the following frameworks:
 - [MWCP](https://github.com/dod-cyber-crime-center/DC3-MWCP)
 - [CAPE w/ MACO output](https://github.com/kevoreilly/CAPEv2)
 - [MACO](https://github.com/CybercentreCanada/Maco)
