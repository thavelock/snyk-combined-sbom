![snyk-oss-category](https://github.com/snyk-labs/oss-images/blob/main/oss-community.jpg)

# Snyk Combined SBOM

* `snyk-combined-sbom` is designed to help create SBOMs for Snyk Targets in a Snyk Org
* How does it work? When the tool is run, it will create a file structure as follows:

```
output
├── target1
│   ├── project-sbom1.json
│   ├── project-sbom2.json
│   ├── project-sbom3.json
│   └── project-sbom4.json
├── target2
│   ├── project-sbom1.json
│   └── project-sbom2.json
└── target3
    └── project-sbom1.json
```

* All output will live under the `/output` directory
* Within `/output`, there will be a number of `/target` directories that will represent targets in your Snyk Org (e.g. git repos, container image scans, etc.)
* Within each `/target` directory will be CycloneDX 1.4 formatted sbom files for each sbom supported project within that target (Open Source and Container projects)
* Once this directory/file structure is created, one could use a tool such as [cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli) to merge all project sboms for a target

## Installation

* Requires `python` version 3
* Requires `poetry` to install dependencies
* Clone the repository and run the following steps

```shell
poetry install
poetry run snyk-combined-sbom
```

## Usage

### `snyk-combined-sbom create`

* This is the main command
* It will create the directory/file structure and retrieve the SBOMs for each supported project (depending on the size of the org it may take a while to run)
* Your Organization ID can be obtained from the Organization settings page in Snyk
* A [Snyk API token](https://docs.snyk.io/snyk-api-info/authentication-for-api) to be able to make API calls

Examples:
```shell

# Print help prompt
poetry run snyk-combined-sbom create --help

# Example where Snyk API token is passed in as parameter
poetry run snyk-combined-sbom create <ORG_ID> --snyk-token=<SNYK_TOKEN>

# Example where Snyk API token is picked up as environment variable: SNYK_TOKEN
poetry run snyk-combined-sbom create <ORG_ID>

# Example where we can filter for a specific origin (e.g. github-enterprise, gitlab, etc.)
poetry run snyk-combined-sbom create <ORG_ID> --origin=github-enterprise
```

### `snyk-combined-sbom clean`

* This can be used to clean up the directory structure (essentially removes the `/output` directory)

Examples:

```shell
poetry run poetry run snyk-combined-sbom clean
```
