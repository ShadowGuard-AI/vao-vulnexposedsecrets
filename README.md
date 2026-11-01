# vao-VulnExposedSecrets
Scans code repositories (local or remote git repos) for exposed secrets (API keys, passwords, etc.) using `detect-secrets`, and orchestrates vulnerability assessments using existing command-line tools (nuclei and testssl.sh; the script only executes these, it does not re-implement them). Findings are reported by tool, file, and location. Matched secret values are masked in every report this tool writes.

External prerequisites, not installed by requirements.txt: `detect-secrets` (a Python package, installed separately), `nuclei`, and `testssl.sh` must be installed and on PATH, and `git` must be installed. A run in which a selected tool is missing, skipped, or failed exits non-zero, names the tools that did not run in the consolidated report tool_statuses, and is marked not_performed_or_incomplete instead of completed.

Schedules offered are daily, weekly, and once. There is no monthly schedule, because the schedule library provides no monthly unit.

## Install
`git clone https://github.com/ShadowStrikeHQ/vao-vulnexposedsecrets`

## Usage
`./vao-vulnexposedsecrets [params]`

## Parameters
- `-h`: Show help message and exit
- `--target`: Target repository (local path or remote git URL), required for the scan command
- `--schedule`: Scan schedule: daily, weekly, or once (default daily)
- `--tools`: Specify which tools to run. Defaults to running all available.
- `--output`: Output file name for the report command

## License
Copyright (c) ShadowStrikeHQ
