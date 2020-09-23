# assemblyline-service-configextractor
This is meant to extract Malware Configuration data from various malware
families and provide a wrapper for popular malware config decoders:
* MWCP framework: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP [MIT license]
* RATDecoder: https://github.com/kevthehermit/RATDecoders [MIT license]
* CAPE Sandbox: https://github.com/kevoreilly/CAPEv2/ [GPL license] (many thanks to @kevoreilly for releasing so many open source parsers).

This wrapper and the AssemblyLine service is released under the MIT license, but includes work released under the GPL license and includes the license and copyright.


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

## Editing the YAML file
 The yara_parser.yaml file is used to run a parser under 3 different scenarios defined under 'selector'.
 * Yara rule match on file
 * Yara rule match on tag
 * Run all parsers
 
 If for either 'yara_rule' or 'tag' a match is found the parser(s) underneath are run.
 Tags come from a previous service(ConfigExtractor runs as a secondary service) 
 If under the 'selector' section 'wildcard' is found, then all parsers defined in the 'parser' section are run.
 
 Adding an entry can be done by following the existing format. In each entry every field must be 
 indented by 2 spaces. Under the 'parser' field different types of parsers will be supported
 (MWCP,CAPE), as of yet only MWCP parsers are supported.
 If 'yara_rule' exists under 'selector' then it must contain at least one or more directories.
 As well if 'tag' exists under 'selector' then it must contain one or more directories.
 If neither 'yara_rule' or 'tag' exist then the only way for parser to run is be added as a 'wildcard'
 parser which will run all parsers defined under it every time a file is submitted.

## Running in CLI mode
ConfigExtractor can also be used in cli mode outside of assemblyline. Ensure that all dependencies are met in requirements.txt and yara and yara-python is installed. run command 'python3 cli.py file\_path' where file\_path is name of file to analyze.

## Adding a new Parser
1. Append entry to yara\_parser.yaml. Following format above. On startup an entry in parser\_config.yml should be created
2. Add yara rule defined in yara\_parser.yaml to yara\_rules directory.
3. Add tag rule defined in yara\_parser.yaml to tag\_rules directory (Optional)
4. Add parser to mwcp\_parsers directory


##### Note
Parser with wildcard in yara_parser.yml are default parsers that are run every time if no other matches are found. As well ensure classification is a valid field ("TLP:A","TLP:W").
