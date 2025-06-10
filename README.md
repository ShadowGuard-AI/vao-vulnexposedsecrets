# vao-VulnExposedSecrets
Scans code repositories (local or remote git repos) for exposed secrets (API keys, passwords, etc.). Uses `detect-secrets` to identify secrets and reports findings with severity based on secret type (e.g., AWS key vs. plaintext password) and location. - Focused on Orchestrates and schedules vulnerability assessments using existing command-line tools (e.g., nuclei, testssl.sh - the python script only *executes* these, not re-implements them). Provides a simple API to define targets, schedule scans, and collect results for analysis. Focuses on simplifying the management of vulnerability scanning at scale by wrapping command line tooling.

## Install
`git clone https://github.com/ShadowStrikeHQ/vao-vulnexposedsecrets`

## Usage
`./vao-vulnexposedsecrets [params]`

## Parameters
- `-h`: Show help message and exit
- `--target`: No description provided
- `--schedule`: No description provided
- `--tools`: Specify which tools to run. Defaults to running all available.
- `--output`: Output file name

## License
Copyright (c) ShadowStrikeHQ
