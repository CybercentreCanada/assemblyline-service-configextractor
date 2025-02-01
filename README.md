[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline_service_configextractor-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-configextractor)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-configextractor)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-configextractor)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-configextractor)](./LICENSE)

# ConfigExtractor Service

This service runs parsers to extract malware configuration data.

## Service Details

This Assemblyline service extracts malware configurations (such as IP, URL and domain) for various malware family by leveraging the [ConfigExtractor Python library](https://github.com/CybercentreCanada/configextractor-py) for analysis.

### Updater

#### Sources

The updater for this service requires matches on directories containing parsers.

For example, the CAPE source will have a match pattern of `^\/tmp\/w+\/CAPE\/$` in which we're trying to target the parsers in the root directory only.

##### Source Configuration

You can the following configuration(s) for a source:

```json
{
    // Set the deployment status of extractors
    "deployment_status": {
        // Set all extractor classes in this list to NOISY on update
        "NOISY": ["extractor_class", ...],
        "DISABLED": ["broken_extractor_class", ...]
    }
}
```

#### Persistence

The updater assumes that you have attached a storage volume to store your collection of sources. Contrary to other services, this updater relies on a storage volume to maintain persistence rather than Assemblyline's datastore.

#### Python Packages

The updater is able to scan through the root directory containing parsers and look for a `requirements.txt` file and install Python packages to a directory that should get passed onto service instances.

If you require a proxy connection for package installation, add environment variable `PIP_PROXY` to the container configuration.

### [ConfigExtractor Python Library](https://github.com/CybercentreCanada/configextractor-py) (now available on [PyPI](https://pypi.org/project/configextractor-py/))

All parser directories that are able to work with this library should also be compatible with the service.

At the time of writing, we officially support the following frameworks:

- [MWCP](https://github.com/dod-cyber-crime-center/DC3-MWCP)
- [CAPE w/ MACO output](https://github.com/kevoreilly/CAPEv2)
- [MACO](https://github.com/CybercentreCanada/Maco)

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Configextractor \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-configextractor

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service ConfigExtractor

Ce service exécute des analyseurs pour extraire les données de configuration des logiciels malveillants.

## Détails du service

Ce service Assemblyline extrait les configurations des logiciels malveillants (telles que l'IP, l'URL et le domaine) pour diverses familles de logiciels malveillants en exploitant la [bibliothèque Python ConfigExtractor] (https://github.com/CybercentreCanada/configextractor-py) à des fins d'analyse.

### Mise à jour

#### Sources

L'outil de mise à jour pour ce service nécessite des correspondances sur les répertoires contenant des analyseurs.

Par exemple, la source CAPE aura un modèle de correspondance de `^\/tmp\/w\+/CAPE\/$` dans lequel nous essayons de cibler les analyseurs dans le répertoire racine uniquement.

##### Configuration de la source

Vous pouvez utiliser les configurations suivantes pour une source :

```json
{
    // Définir l'état de déploiement des extracteurs
    "deployment_status" : {
        // Définit toutes les classes d'extracteurs de cette liste comme NOISY lors de la mise à jour
        "NOISY" : ["extractor_class", ...],
        "DISABLED" : ["broken_extractor_class", ...]
    }
}
```

Traduit avec DeepL.com (version gratuite)

#### Persistance

Le service de mise à jour suppose que vous avez attaché un volume de stockage pour stocker votre collection de sources. Contrairement à d'autres services, cet outil de mise à jour s'appuie sur un volume de stockage pour maintenir la persistance plutôt que sur le magasin de données d'Assemblyline.

#### Paquets Python

L'outil de mise à jour est capable de parcourir le répertoire racine contenant les analyseurs et de rechercher un fichier `requirements.txt` et d'installer des paquets Python dans un répertoire qui doit être transmis aux instances du service.

Si vous avez besoin d'une connexion proxy pour l'installation des paquets, ajoutez la variable d'environnement `PIP_PROXY` à la configuration du conteneur.

### [ConfigExtractor Python Library](https://github.com/CybercentreCanada/configextractor-py) (maintenant disponible sur [PyPI](https://pypi.org/project/configextractor-py/))

Tous les répertoires d'analyseurs qui sont capables de fonctionner avec cette bibliothèque devraient également être compatibles avec le service.

Au moment de la rédaction de ce document, nous supportons officiellement les frameworks suivants:

- [MWCP](https://github.com/dod-cyber-crime-center/DC3-MWCP)
- [CAPE w/ MACO output](https://github.com/kevoreilly/CAPEv2)
- [MACO](https://github.com/CybercentreCanada/Maco)

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Configextractor \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-configextractor

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/

---

# Contributions ✨

Thanks to everyone who have contributed to this project/Merci à tous ceux qui ont contribué à ce projet:

|                                                                                       Contributor/Contributeur                                                                                       | Contribution(s)                                                                                                                      |                                                                       License/Licence                                                                       |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | ------------------------------------------------------------------------------------------------------------------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------: |
|              <a href="https://github.com/jeFF0Falltrades"><img src="https://images.weserv.nl/?url=github.com/jeFF0Falltrades.png?v=4&h=75&w=75&fit=cover&mask=circle&maxage=7d"/> </a>               | Added MACO extractors in/Ajout des extracteurs MACO dans:<br> [rat_king_parser](https://github.com/jeFF0Falltrades/rat_king_parser)  | [![License](https://img.shields.io/github/license/jeFF0Falltrades/rat_king_parser)](https://github.com/jeFF0Falltrades/rat_king_parser/blob/master/LICENSE) |
| <a href="https://github.com/apophis133"><img src="https://images.weserv.nl/?url=github.com/apophis133.png?v=4&h=75&w=75&fit=cover&mask=circle&maxage=7d" style="border-radius: 50%;width: 75px"></a> | Added MACO extractors in/Ajout des extracteurs MACO dans:<br> [apophis-YARA-Rules](https://github.com/apophis133/apophis-YARA-Rules) |                                                                                                                                                             |
| <a href="https://github.com/kevoreilly"><img src="https://images.weserv.nl/?url=github.com/kevoreilly.png?v=4&h=75&w=75&fit=cover&mask=circle&maxage=7d" style="border-radius: 50%;width: 75px"></a> | Added MACO extractors in/Ajout des extracteurs MACO dans:<br> [CAPESandbox community](https://github.com/CAPESandbox/community)      |             [![License](https://img.shields.io/badge/license-GPL--3.0-informational)](https://github.com/kevoreilly/CAPEv2/blob/master/LICENSE)             |
