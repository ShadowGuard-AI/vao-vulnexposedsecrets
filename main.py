import argparse
import subprocess
import json
import logging
import os
import schedule
import time
import hashlib
import tempfile
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DEFAULT_SCHEDULE = "daily"  # Default scan schedule
VALID_SCHEDULES = ["daily", "weekly", "once"]  # The schedule library has no monthly unit, so monthly is not offered
SECRETS_REPORT_FILENAME = "secrets_report.json"
NUCLEI_REPORT_FILENAME = "nuclei_report.jsonl"
TESTSSL_REPORT_FILENAME = "testssl_report.json"
VULN_REPORT_FILENAME = NUCLEI_REPORT_FILENAME  # Kept for compatibility; nuclei output only


def mask_secret_values(obj):
    """Recursively mask values held under secret-like keys."""
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            lowered = str(key).lower()
            if isinstance(value, str) and "[REDACTED" not in value and any(word in lowered for word in ("secret", "password", "token", "api_key", "apikey")):
                # Masking keeps the first four characters plus a short hash prefix. That is enough to match two reports against each other and tell whether a value changed, and it is also the first four characters of a secret in plain view, so I would not share a masked report further than I would share the finding itself.
                digest = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:8]
                out[key] = f"{value[:4]}...[REDACTED sha256:{digest}]"
            else:
                out[key] = mask_secret_values(value)
        return out
    # Only string values under a secret sounding key get masked. A secret sitting under a plain key like line or value passes through untouched, and a non string secret is recursed into or returned as is, so this is a filter for the known report shapes, not a guarantee about the file.
    if isinstance(obj, list):
        return [mask_secret_values(item) for item in obj]
    return obj

def setup_argparse():
    """Sets up the argument parser for the CLI."""
    parser = argparse.ArgumentParser(description="Orchestrates vulnerability assessments and secret scanning.")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan for vulnerabilities and secrets")
    scan_parser.add_argument("--target", required=True, help="Target repository (local path or remote git URL)")
    scan_parser.add_argument("--schedule", default=DEFAULT_SCHEDULE, choices=VALID_SCHEDULES,
                             help=f"Scan schedule: {', '.join(VALID_SCHEDULES)}. Defaults to {DEFAULT_SCHEDULE}")
    scan_parser.add_argument("--tools", nargs="+", choices=["detect-secrets", "nuclei", "testssl.sh"],
                             help="Specify which tools to run. Defaults to running all available.")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate a consolidated report")
    report_parser.add_argument("--output", help="Output file name")


    # list-tools command
    list_tools_parser = subparsers.add_parser("list-tools", help="List available scanning tools.")


    return parser

def is_git_repository(path):
    """Checks if the given path is a git repository."""
    try:
        # Check if the .git directory exists
        if os.path.isdir(os.path.join(path, ".git")):
            return True

        # If not, check if we are in a git repository using git rev-parse
        # The rev-parse fallback means a target that is a subfolder of a larger repository counts as a repository. The check passes on the strength of the parent repo, while the scan itself only walks the folder it was given.
        result = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=path, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip() == "true":
            return True
        else:
            return False
    except FileNotFoundError:
        # Git is not installed
        return False
    except Exception as e:
        logging.error(f"Error checking git repository: {e}")
        return False


def clone_repository(repo_url, destination_path):
    """Clones a git repository to the specified destination."""
    try:
        logging.info(f"Cloning repository: {repo_url} to {destination_path}")
        subprocess.run(["git", "clone", repo_url, destination_path], check=True, capture_output=True, text=True)
        logging.info(f"Repository cloned successfully to: {destination_path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error cloning repository: {e.stderr}")
        raise
    except FileNotFoundError:
        logging.error("Git is not installed. Please install git.")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise

def scan_secrets(target):
    """Scans the target repository for exposed secrets using detect-secrets."""
    logging.info(f"Scanning for secrets in: {target}")
    try:
        # detect-secrets writes its JSON report to stdout; the scanned
        # path is the only scan argument. Capture and parse that JSON.
        command = ["detect-secrets", "scan", target]
        result = subprocess.run(command, check=False, capture_output=True, text=True)

        if result.returncode != 0:
            logging.error(f"detect-secrets returned a non-zero exit code: {result.returncode}. Error Output: {result.stderr}")
            return False

        stdout = (result.stdout or "").strip()
        if stdout:
            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError as e:
                logging.error(f"Could not parse detect-secrets JSON output: {e}")
                return False
        else:
            parsed = {}

        with open(SECRETS_REPORT_FILENAME, 'w') as f:
            json.dump(mask_secret_values(parsed), f, indent=4)

        logging.info("Secret scanning completed.")


    except FileNotFoundError:
        logging.error("detect-secrets not found. Please install it: pip install detect-secrets")
        return False
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running detect-secrets: {e.stderr}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during secret scanning: {e}")
        return False

    return True


def run_nuclei(target):
    """Runs nuclei against the given target."""
    logging.info(f"Running Nuclei against: {target}")
    try:
        # Validate target - rudimentary URL check
        if not re.match(r'^(http|https)://', target):
            logging.warning(f"Target {target} doesn't appear to be a URL.  Skipping Nuclei scan.  Consider prepending with http:// or https://")
            return False  # Nuclei expects a URL

        command = ["nuclei", "-u", target, "-json", "-o", NUCLEI_REPORT_FILENAME]
        result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            logging.error(f"Nuclei returned a non-zero exit code: {result.returncode}. Error Output: {result.stderr}")
            return False
        logging.info(f"Nuclei scan completed. Output saved to {NUCLEI_REPORT_FILENAME}")

    except FileNotFoundError:
        logging.error("Nuclei not found. Please install it: refer to projectnuclei.io")
        return False
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running Nuclei: {e.stderr}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during Nuclei scan: {e}")
        return False
    return True

def run_testssl(target):
    """Runs testssl.sh against the given target."""
    logging.info(f"Running testssl.sh against: {target}")

    try:
        command = ["testssl.sh", "--jsonfile", TESTSSL_REPORT_FILENAME, target]
        result = subprocess.run(command, capture_output=True, text=True, check=False)  # Allow non-zero exit codes

        if result.returncode != 0:
            logging.error(f"testssl.sh returned a non-zero exit code: {result.returncode}. Error output: {result.stderr}")
            return False
        logging.info(f"testssl.sh scan completed. Output saved to {TESTSSL_REPORT_FILENAME}")

    except FileNotFoundError:
        logging.error("testssl.sh not found.  Ensure it's installed and in your PATH.")
        return False
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running testssl.sh: {e.stderr}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during testssl.sh scan: {e}")
        return False

    return True


def consolidate_reports(output_filename="consolidated_report.json", tool_statuses=None, scan_status=None):
    """Consolidates the reports generated by different tools into a single JSON file."""
    logging.info("Consolidating reports...")
    consolidated_data = {}
    if tool_statuses is not None:
        consolidated_data["tool_statuses"] = tool_statuses
    if scan_status is not None:
        consolidated_data["scan_status"] = scan_status
    # Secrets report: distinguish not performed, performed with no
    # findings, and performed with findings.
    if os.path.exists(SECRETS_REPORT_FILENAME):
        with open(SECRETS_REPORT_FILENAME, "r") as f:
            secrets_data = mask_secret_values(json.load(f))
        results_map = secrets_data.get("results", {}) if isinstance(secrets_data, dict) else {}
        has_findings = bool(results_map) and any(results_map.values())
        # This reads whatever secrets report file sits in the working directory. If the current run failed before writing a fresh one, a file left by an earlier run is consolidated under this runs statuses, and only the file timestamps would tell a reader it was stale.
        consolidated_data["secrets"] = {
            "status": "performed_with_findings" if has_findings else "performed_no_findings",
            "report": secrets_data,
        }
    else:
        consolidated_data["secrets"] = {"status": "not_performed"}

    # Vulnerability reports: nuclei writes JSON lines, testssl.sh
    # writes a single JSON document, each in its own file.
    vuln = {}
    if os.path.exists(NUCLEI_REPORT_FILENAME):
        entries = []
        with open(NUCLEI_REPORT_FILENAME, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        # A line that fails to parse is logged and dropped, not counted anywhere. The consolidated list can therefore be shorter than the file nuclei wrote, with the only trace in the log of a run that may already be over.
                        entries.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        logging.error(f"Error decoding a nuclei output line: {e}")
        vuln["nuclei"] = entries
    if os.path.exists(TESTSSL_REPORT_FILENAME):
        with open(TESTSSL_REPORT_FILENAME, "r") as f:
            try:
                vuln["testssl"] = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding testssl report: {e}")
                vuln["testssl"] = {"error": "Failed to decode testssl report."}
    consolidated_data["vulnerabilities"] = vuln if vuln else {"status": "not_performed"}

    with open(output_filename, "w") as outfile:
        json.dump(consolidated_data, outfile, indent=4)

    logging.info(f"Consolidated report saved to: {output_filename}")
    return consolidated_data

def perform_scan(target, tools=None):
    """Performs the vulnerability and secret scanning.

    Returns a tuple (ok, statuses) where statuses maps each selected
    tool to one of: ran, missing, skipped, failed. ok is True only
    when every selected tool ran successfully.
    """
    temp_dir = None # Holds the temporary directory if a clone is needed
    statuses = {}

    try:
        # Determine if the target is a local path or a remote git repository
        if re.match(r'^(http|https)://', target):
            # Assume it is a remote repository URL
            logging.info(f"Target '{target}' looks like a remote URL - attempting to clone.")
            # The clone lands in the working directory, not the system temp area, because the report files also live here and the tools expect to run where they were started. The finally below removes it, but a killed process leaves the clone behind with the scan target inside it.
            temp_dir = tempfile.mkdtemp(prefix="temp_repo_", dir=".")
            clone_repository(target, temp_dir)
            scan_target = temp_dir # Set the path to scan to the cloned repo
        elif os.path.isdir(target):
            # It's a local directory
            logging.info(f"Target '{target}' is a local directory - using it directly.")
            scan_target = target
        else:
            logging.error(f"Invalid target: {target}. Must be a valid directory path or a remote git URL.")
            return (False, statuses)

        # Check if the target is a git repository
        if not is_git_repository(scan_target):
            logging.error(f"Target '{scan_target}' is not a valid git repository.")
            return (False, statuses)

        # If no tools are specified, run all available tools
        if not tools:
            tools = ["detect-secrets", "nuclei", "testssl.sh"]

        def _record(name, ran_ok, missing_hint):
            if ran_ok:
                statuses[name] = "ran"
            else:
                # A False result from a tool that is not on PATH is a
                # missing tool; the tool functions already logged which.
                import shutil as _shutil
                # Missing versus failed is decided after the fact, by looking the tool up on PATH a second time. A tool that was present and crashed reads as failed, and one that was never there reads as missing, but a tool removed mid run would be mislabelled, because the lookup is not the run.
                statuses[name] = "missing" if _shutil.which(name) is None else "failed"
                logging.error(f"Tool {name} did not run successfully ({missing_hint}).")

        if "detect-secrets" in tools:
            _record("detect-secrets", scan_secrets(scan_target), "see log")

        if "nuclei" in tools:
            if re.match(r'^(http|https)://', target):
                _record("nuclei", run_nuclei(target), "see log")
            else:
                statuses["nuclei"] = "skipped"
                logging.info("Skipping Nuclei execution because target is not a URL.")

        if "testssl.sh" in tools:
            if re.match(r'^(http|https)://', target):
                _record("testssl.sh", run_testssl(target), "see log")
            else:
                statuses["testssl.sh"] = "skipped"
                logging.info("Skipping testssl.sh as it only supports URLs.")

        missing = [name for name, status in statuses.items() if status != "ran"]
        if missing:
            logging.error(f"Scan not fully performed. Tools not run successfully: {', '.join(missing)}")
            return (False, statuses)
        return (True, statuses)

    except Exception as e:
        logging.error(f"An error occurred during the scan: {e}")
        return (False, statuses)
    finally:
        # Clean up the temporary directory if it was created
        if temp_dir and os.path.exists(temp_dir):
            try:
                import shutil
                shutil.rmtree(temp_dir)
                logging.info(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                logging.error(f"Failed to remove temporary directory: {temp_dir}.  Manual removal may be needed. Error: {e}")

def schedule_scan(target, schedule_type, tools=None):
    """Schedules the vulnerability and secret scanning based on the schedule type."""

    def scheduled_job():
        logging.info(f"Starting scheduled scan for target: {target}")
        ok, statuses = perform_scan(target, tools)
        if ok:
            logging.info(f"Scheduled scan for target: {target} completed successfully.")
            consolidate_reports(tool_statuses=statuses, scan_status="completed")
            return True
        logging.error(f"Scheduled scan for target: {target} failed or was not fully performed: {statuses}")
        if statuses:
            consolidate_reports(tool_statuses=statuses, scan_status="not_performed_or_incomplete")
        return False

    if schedule_type == "daily":
        schedule.every().day.do(scheduled_job)
    elif schedule_type == "weekly":
        schedule.every().week.do(scheduled_job)
    elif schedule_type == "once":
        return scheduled_job() # Run immediately, no scheduling loop
    else:
        logging.error(f"Invalid schedule type: {schedule_type}")
        return False

    logging.info(f"Scan scheduled for target: {target} with schedule: {schedule_type}")
    # This loop has no exit of its own. A scheduled run ends only when the process is killed or the job raises, so whoever starts a daily scan owns stopping it, and the log is the only record it ever ran.
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute



def main():
    """Main function to parse arguments and run the scanning process."""
    parser = setup_argparse()
    args = parser.parse_args()

    if args.command == "scan":
        try:
            if args.schedule == "once":
                ok, statuses = perform_scan(args.target, args.tools)
                if ok:
                    consolidate_reports(tool_statuses=statuses, scan_status="completed")
                elif statuses:
                    consolidate_reports(tool_statuses=statuses, scan_status="not_performed_or_incomplete")
                    logging.error("Scan not performed or incomplete. See tool statuses in the consolidated report.")
                    sys.exit(1)
                else:
                    logging.error("Scan failed.")
                    sys.exit(1)
            else:
                result = schedule_scan(args.target, args.schedule, args.tools)
                if result is False:
                    sys.exit(1)
        except SystemExit:
            raise
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            sys.exit(1)

    elif args.command == "report":
        consolidate_reports(args.output or "consolidated_report.json")
    elif args.command == "list-tools":
        print("Available tools: detect-secrets, nuclei, testssl.sh")
        print("External prerequisites: detect-secrets, nuclei, and testssl.sh must be installed and on PATH, and git must be installed.")
    elif not args.command:
        parser.print_help()  # Print help if no command is given
        sys.exit(2)
    else:
        print(f"Unknown command: {args.command}")
        sys.exit(2)



if __name__ == "__main__":
    main()
