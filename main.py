import argparse
import subprocess
import json
import logging
import os
import schedule
import time
import shlex
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DEFAULT_SCHEDULE = "daily"  # Default scan schedule
VALID_SCHEDULES = ["daily", "weekly", "monthly", "once"]  # Valid scan schedules
SECRETS_REPORT_FILENAME = "secrets_report.json"
VULN_REPORT_FILENAME = "vulnerability_report.json"

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
        # Run detect-secrets command
        command = ["detect-secrets", "scan", "--json", SECRETS_REPORT_FILENAME, target]
        result = subprocess.run(command, check=False, capture_output=True, text=True)  # Do not raise on non-zero exit code

        if result.returncode != 0 and "No secrets found!" not in result.stderr:
            logging.warning(f"detect-secrets returned a non-zero exit code: {result.returncode}. Error Output: {result.stderr}")
        elif "No secrets found!" in result.stderr:
            logging.info("No secrets found in the repository.")
            # Create an empty JSON file to indicate no secrets found
            with open(SECRETS_REPORT_FILENAME, 'w') as f:
                json.dump({}, f)

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

        command = ["nuclei", "-u", target, "-json", "-o", VULN_REPORT_FILENAME]
        result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            logging.warning(f"Nuclei returned a non-zero exit code: {result.returncode}. Error Output: {result.stderr}")
        else:
            logging.info(f"Nuclei scan completed. Output saved to {VULN_REPORT_FILENAME}")

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
        command = ["testssl.sh", "--jsonfile", VULN_REPORT_FILENAME, target]
        result = subprocess.run(command, capture_output=True, text=True, check=False)  # Allow non-zero exit codes

        if result.returncode != 0:
            logging.warning(f"testssl.sh returned a non-zero exit code: {result.returncode}. Error output: {result.stderr}")
        else:
            logging.info(f"testssl.sh scan completed. Output saved to {VULN_REPORT_FILENAME}")

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


def consolidate_reports(output_filename="consolidated_report.json"):
    """Consolidates the reports generated by different tools into a single JSON file."""
    logging.info("Consolidating reports...")
    consolidated_data = {}
    try:
        # Load secrets report
        if os.path.exists(SECRETS_REPORT_FILENAME):
            with open(SECRETS_REPORT_FILENAME, "r") as f:
                consolidated_data["secrets"] = json.load(f)
        else:
            consolidated_data["secrets"] = {"status": "No secrets scan performed or no secrets found."}

        # Load vulnerability report
        if os.path.exists(VULN_REPORT_FILENAME):
            with open(VULN_REPORT_FILENAME, "r") as f:
                try:
                    consolidated_data["vulnerabilities"] = json.load(f)
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding vulnerability report: {e}.  The file might be invalid JSON or empty.")
                    consolidated_data["vulnerabilities"] = {"error": "Failed to decode vulnerability report.  Check logs for details."}

        else:
            consolidated_data["vulnerabilities"] = {"status": "No vulnerability scans performed."}


        # Write consolidated report to file
        with open(output_filename, "w") as outfile:
            json.dump(consolidated_data, outfile, indent=4)

        logging.info(f"Consolidated report saved to: {output_filename}")

    except FileNotFoundError as e:
        logging.error(f"Report file not found: {e}")
    except Exception as e:
        logging.error(f"An error occurred during report consolidation: {e}")

def perform_scan(target, tools=None):
    """Performs the vulnerability and secret scanning."""
    temp_dir = None # Holds the temporary directory if a clone is needed

    try:
        # Determine if the target is a local path or a remote git repository
        if re.match(r'^(http|https)://', target):
            # Assume it is a remote repository URL
            logging.info(f"Target '{target}' looks like a remote URL - attempting to clone.")
            temp_dir = "temp_repo"
            os.makedirs(temp_dir, exist_ok=True)  # Create the directory if it does not exist
            clone_repository(target, temp_dir)
            scan_target = temp_dir # Set the path to scan to the cloned repo
        elif os.path.isdir(target):
            # It's a local directory
            logging.info(f"Target '{target}' is a local directory - using it directly.")
            scan_target = target
        else:
            logging.error(f"Invalid target: {target}. Must be a valid directory path or a remote git URL.")
            return False

        # Check if the target is a git repository
        if not is_git_repository(scan_target):
            logging.error(f"Target '{scan_target}' is not a valid git repository.")
            return False

        # If no tools are specified, run all available tools
        if not tools:
            tools = ["detect-secrets", "nuclei", "testssl.sh"]

        # Run the specified tools
        if "detect-secrets" in tools:
            scan_secrets(scan_target)

        # Run Nuclei if target looks like a URL or a valid directory
        if "nuclei" in tools and (re.match(r'^(http|https)://', target) or os.path.isdir(target)):
            if re.match(r'^(http|https)://', target):
                 run_nuclei(target)  # Run Nuclei directly against the URL
            else:
                logging.info("Skipping Nuclei execution because target is not a URL.")

        if "testssl.sh" in tools:
            if re.match(r'^(http|https)://', target):
                run_testssl(target)
            else:
                logging.info("Skipping testssl.sh as it only supports URLs.")



        return True

    except Exception as e:
        logging.error(f"An error occurred during the scan: {e}")
        return False
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
        if perform_scan(target, tools):
            logging.info(f"Scheduled scan for target: {target} completed successfully.")
            consolidate_reports() # Generate a report automatically
        else:
            logging.error(f"Scheduled scan for target: {target} failed.")

    if schedule_type == "daily":
        schedule.every().day.do(scheduled_job)
    elif schedule_type == "weekly":
        schedule.every().week.do(scheduled_job)
    elif schedule_type == "monthly":
        schedule.every().month.do(scheduled_job)
    elif schedule_type == "once":
        scheduled_job() # Run immediately
        return # Don't enter the scheduling loop
    else:
        logging.error(f"Invalid schedule type: {schedule_type}")
        return

    logging.info(f"Scan scheduled for target: {target} with schedule: {schedule_type}")
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
                 if perform_scan(args.target, args.tools):
                     consolidate_reports() # generate a report after execution.
                 else:
                     logging.error("Scan failed.")
            else:
                schedule_scan(args.target, args.schedule, args.tools)
        except Exception as e:
            logging.error(f"An error occurred: {e}")

    elif args.command == "report":
        consolidate_reports(args.output or "consolidated_report.json")
    elif args.command == "list-tools":
        print("Available tools: detect-secrets, nuclei, testssl.sh")
    elif not args.command:
        parser.print_help()  # Print help if no command is given
    else:
        print(f"Unknown command: {args.command}")



if __name__ == "__main__":
    main()