# ConfigExtractor Service
This service wraps the MWCP framework. Meant to extract Malware Configuration data from various malware
families. Runs yara rules on files as well as service tags to determine which parsers to run.



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

### CLI Usage
 Run `python3.7 cli.py "file"` where "file" is replaced with path of file
##### Note
Parser with wildcard in yara_parser.yml are default parsers that are run every time if no other matches are found.

