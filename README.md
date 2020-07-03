# assemblyline-service-configextractor
This is meant to extract Malware Configuration data from various malware
families and provide a wrapper for popular malware config decoders:
* MWCP framework: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP [MIT license]
* RATDecoder: https://github.com/kevthehermit/RATDecoders [MIT license]
* CAPE Sandbox: https://github.com/kevoreilly/CAPEv2/ [GPL license] (many thanks to @kevoreilly for releasing so many open source parsers).

This wrapper and the AssemblyLine service is released as MIT, but include work released under the GPL license and include the license and copyright.

yara_parser.yaml is used to trigger parser based on: a Yara rule, AssemblyLine Tag Found or for any file.

## Service structure

This service has the following file structure:
```text
assemblyline-service-configextractor
│
├── cli.py
├── configextractor.py
├── Dockerfile
├── fields.json
├── mwcp_parsers
│   ├── Azorult.py
│   ├── ...
├── tag_rules
│   └── tagcheck.rules
├── yara_parser.yaml
├── yara_rules
│   ├── azorult.yara
│   ├── ...
...
```

This is overview of each of these :

* `cli.py` ─ Runs configextractor in cli mode
* `configextractor.py` - Service that runs in Assemblyline
* `fields.json` valid parser fields that MWCP supports
* `mwcp_parsers` ─ Directory containing all MWCP parsers, additional parsers go in here.
* `tag_rules` - Contains rules to run on tags from previous services.
* `yara_parser.yaml` ─ Contains Parser Entries, mandatory.
* `yara_rules` - Contains yara rules for parsers.

## Adding a new Parser
1. Add yara rule defined in yara_parser.yaml to yara_rules directory.
2. Add tag rule defined in yara_parser.yaml to tag_rules directory (Optional)
3. Add parser to mwcp_parsers directory

##### Note
Parser with wildcard in yara_parser.yml are default parsers that are run every time if no other matches are found.
