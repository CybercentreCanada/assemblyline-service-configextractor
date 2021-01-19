# ConfigExtractor Service
This service extract malware configuration (such as IP, URL and domain) for various malware family. Most of the time this is only possible on unpacked version of malware such as in a memory dump. See our Cuckoo service to automate extraction of malware memory dump.

The code found in this repository contains two main aspects: the Assemblyline service code
(configextractor.py) and the command line interface (cli.py). The Assemblyline service code
utilizes cli.py in order to perform Assemblyline related functionality, 
but the command line interface can be used exclusively. The command line interface acts as 
a wrapper for popular malware configuration data decoders from:
* MWCP framework: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP [MIT license]
* RATDecoder: https://github.com/kevthehermit/RATDecoders [MIT license]
* CAPE Sandbox: https://github.com/kevoreilly/CAPEv2/ [GPL license] (many thanks to @kevoreilly for releasing so many open source parsers).

This wrapper and the AssemblyLine service is released under the MIT license, but includes work released under the GPL license and includes the license and copyright.


## Service structure

This service has the following file structure:
```text
assemblyline-service-configextractor
.
├── Dockerfile
├── cli.py
├── configextractor.py
├── service_manifest.yml
├── __init__.py
├── LICENSE
├── README.md
├── requirements.txt
├── wrapper_malconfs.py
├── pipelines
│   └── azure-build.yaml
├── mwcp_parsers
│   ├── parser_config.yaml
│   ├── __init__.py
│   ├── example_parser.py
│   └── ...
├── tag_rules
│   ├── example_tag_rule.rules
│   └── ...
├── yara_parser.yaml
├── yara_rules
│  ├── example_yara_rule.yara
|  └── ...
└── RATDecoders
  └── clone of https://github.com/kevthehermit/RATDecoders
```

This is an overview of each of the major parts of this project :

* `cli.py` ─ Command line interface that acts as wrapper for config extractor decoders
* `configextractor.py` - Service code that runs in Assemblyline
* `wrapper_malconf.py` ─ wrapper for TechAnarchy RATDecoders
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

## Customization
When creating a new MWCP parser, follow the setup [here](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/blob/master/docs/ParserDevelopment.md)

## Example entry in yara_parser.yaml
```text

Emotet:
  description: Emotet parser and yara rule for payload 
  selector: # yara rules that match will run parser(s) defined under parser
    yara_rule:
      - ./yara_rules/emotet.yara # rule must be present in yara_rules directory
  parser: 
      - MWCP:  
        - Emotet # Emotet.py must be in mwcp_parsers directory, case matters

# Another example

Emotet:
  description: Emotet parser and yara rules for both payload and assemblyline tags
  classification: 'TLP:W' # output result classification; may be ommitted
  category: 'MALWARE'
  mitre_group: 'APTXX'  # actor/mitre_group from "https://attack.mitre.org/groups/"
  mitre_att: 'S0367'  # any valid MITRE ATT&CK ID codes
  malware: 'Emotet'  # the malware name that shows up in assemblyline implant tags
  malware_type: # any field from malware_types https://github.com/CybercentreCanada/CCCS-Yara/blob/master/CCCS_YARA_values.yml
    - 'Banker'
    - 'Loader'
  run_on: 'AND' # can be and/or, specifies whether either tag or file rule cause parsers to run or ifall rules have to match in order for parser to run
  selector: # at least one of the rules in yara_rule or tag must be positive for parser to run
    yara_rule: # both rules beneath will be run on file
      - ./yara_rules/emotet.yara # one or more rules may be added
      - ./yara_rules/emotet2.yara 
      
    tag: # can be ommitted completely if yara_rule is present
      - ./tag_rules/emotet.rule # one or more rules may be added
      -./tag_rules/emotet2.rule
  parser: 
      - MWCP:  # Multiple malware parsers will be run upon yara rule match 
        - Emotet
        - QakBot
        - IcedID




```
## Running in CLI mode
ConfigExtractor can also be used in cli mode outside of Assemblyline. Ensure that all dependencies are met in requirements.txt and yara and yara-python is installed. run command 'python3 cli.py file\_path' where file\_path is name of file to analyze.
## Adding Tag rule
Since ConfigExtractor is a secondary service; all tags created by core services are available to determine whether a particular parser should be run.
Yara rules can either be run on files or Assemblyline tags.
A parser will run if the corresponding yara rule finds a match on an Assemblyline tag.

For example a rule can be created to run an Emotet parser if an "attribution.implant:Emotet" tag is found.
The yara rule could look like this. This yara rule would have to exactly match "EMOTET", other regex patterns can be defined as well.
```text  
rule emotet_tag {

	meta:
		version = "1.0"
		description = "Identifies emotet by attribution.implant"
		source = "CCCS"
		author = "assemblyline"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "TECHNIQUE"
		technique = "packer:UPX"

	condition:
		al_attribution_implant matches /EMOTET/
}
```
 
## Adding a new Parser
1. Append entry to yara\_parser.yaml. Following format above. On startup an entry in parser\_config.yml should be created
2. Add yara rule defined in yara\_parser.yaml to yara\_rules directory.
3. Add tag rule defined in yara\_parser.yaml to tag\_rules directory (Optional)
4. Add parser to mwcp\_parsers directory


##### Note
Parser with wildcard in yara_parser.yml are default parsers that are run every time if no other matches are found. As well ensure classification is a valid field ("TLP:A","TLP:W").
