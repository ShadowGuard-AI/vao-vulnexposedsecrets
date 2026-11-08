# vao-VulnExposedSecrets
Scans code repositories (local or remote git repos) for exposed secrets (API keys, passwords, etc.) using `detect-secrets`, and orchestrates vulnerability assessments using existing command-line tools (nuclei and testssl.sh; the script only executes these, it does not re-implement them). Findings are reported by tool, file, and location. Secret values are masked in the reports this tool writes, including values embedded in a finding's source line; a finding's hashed_secret value is left as is, because it is already a hash.

External prerequisites, not installed by requirements.txt: `detect-secrets` (a Python package, installed separately), `nuclei`, and `testssl.sh` must be installed and on PATH, and `git` must be installed. A run in which a selected tool is missing, skipped, or failed exits non-zero, names the tools that did not run in the consolidated report tool_statuses, and is marked not_performed_or_incomplete instead of completed. A secrets report file that cannot be decoded is reported as unreadable in the consolidated report instead of crashing the consolidation.

Schedules offered are daily, weekly, and once. There is no monthly schedule, because the schedule library provides no monthly unit.

## Install
`git clone https://github.com/ShadowGuard-AI/vao-vulnexposedsecrets`

## Usage
`python3 main.py scan --target <local path or remote git URL> [--schedule daily|weekly|once] [--tools detect-secrets nuclei testssl.sh]`

`python3 main.py report [--output <file>]`

`python3 main.py list-tools`

## Parameters
- `-h`: Show help message and exit
- `--target`: Target repository (local path or remote git URL), required for the scan command
- `--schedule`: Scan schedule: daily, weekly, or once (default daily)
- `--tools`: Specify which tools to run. Defaults to running all available.
- `--output`: Output file name for the report command

## License
MIT. See LICENSE.
