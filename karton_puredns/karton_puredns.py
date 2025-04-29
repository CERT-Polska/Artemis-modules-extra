import logging
import tempfile
import subprocess
import os
import sys
from typing import List, Dict, Any, Tuple

from artemis_base.artemis_base import ArtemisBase
from artemis_base.models import TaskStatus, TaskType, Task
from karton.core import Task


class PurednsModule(ArtemisBase):
    """
    Puredns karton module
    """

    identity = "puredns"
    filters = [
        {"type": TaskType.DOMAIN.value},
        {"type": TaskType.DOMAIN_LIST.value},
        {"type": TaskType.SUBDOMAIN_BRUTEFORCE.value},
    ]

    def run(self, current_task: Task) -> None:
        """
        Main entry point that processes tasks based on their type.
        
        Extracts task type from current_task headers, calls the appropriate
        processing method, and saves results to the database with appropriate status.
        """
        # Initialize result variables
        result_data = {}
        has_results = False
        status = TaskStatus.OK
        status_reason = None
        
        try:
            task_type = TaskType(current_task.headers["type"])
            self.log.info(f"Processing task of type {task_type}")
            
            # Process based on task type
            if task_type == TaskType.DOMAIN:
                domain = current_task.payload.get("domain")
                if not domain:
                    self.log.error("Missing domain in payload for DOMAIN task")
                    status = TaskStatus.ERROR
                    status_reason = "Missing domain in payload"
                    result_data = {"error": "Missing domain in payload"}
                    self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result_data)
                    return
                    
                self.log.info(f"Processing domain task for {domain}")
                # Call process_domain and get results
                valid_domains, wildcard_domains = self.process_domain(current_task)
                
                result_data = {
                    "domain": domain,
                    "valid_domains": valid_domains,
                    "wildcard_domains": wildcard_domains
                }
                has_results = len(valid_domains) > 0
                    
            elif task_type == TaskType.DOMAIN_LIST:
                domains = current_task.payload.get("domains")
                if not domains or not isinstance(domains, list):
                    self.log.error("Missing or invalid domains in payload for DOMAIN_LIST task")
                    status = TaskStatus.ERROR
                    status_reason = "Missing or invalid domains in payload"
                    result_data = {"error": "Missing or invalid domains in payload"}
                    self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result_data)
                    return
                
                if len(domains) == 0:
                    self.log.warning("Empty domains list in payload for DOMAIN_LIST task")
                    status = TaskStatus.OK
                    status_reason = "Empty domains list"
                    result_data = {"warning": "Empty domains list", "domains": []}
                    self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result_data)
                    return
                
                self.log.info(f"Processing domain list task with {len(domains)} domains")
                # Call process_domain_list and get results
                valid_domains, wildcard_domains = self.process_domain_list(current_task)
                
                result_data = {
                    "domains": domains,
                    "valid_domains": valid_domains,
                    "wildcard_domains": wildcard_domains
                }
                has_results = len(valid_domains) > 0
                    
            elif task_type == TaskType.SUBDOMAIN_BRUTEFORCE:
                domain = current_task.payload.get("domain")
                if not domain:
                    self.log.error("Missing domain in payload for SUBDOMAIN_BRUTEFORCE task")
                    status = TaskStatus.ERROR
                    status_reason = "Missing domain in payload"
                    result_data = {"error": "Missing domain in payload"}
                    self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result_data)
                    return
                
                self.log.info(f"Performing subdomain bruteforce for {domain}")
                # Call perform_subdomain_bruteforce and get results
                subdomains, wildcard_domains = self.perform_subdomain_bruteforce(current_task)
                
                result_data = {
                    "root_domain": domain,
                    "subdomains": subdomains,
                    "wildcard_domains": wildcard_domains
                }
                has_results = len(subdomains) > 0
                    
            else:
                self.log.error(f"Unsupported task type: {task_type}")
                status = TaskStatus.ERROR
                status_reason = f"Unsupported task type: {task_type}"
                result_data = {"error": f"Unsupported task type: {task_type}"}
                self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result_data)
                return
                
            # Determine task status based on results
            if has_results:
                status = TaskStatus.INTERESTING
                if task_type == TaskType.DOMAIN:
                    status_reason = f"Found {len(result_data['valid_domains'])} valid domains for {current_task.payload.get('domain')}"
                elif task_type == TaskType.DOMAIN_LIST:
                    status_reason = f"Found {len(result_data['valid_domains'])} valid domains in list"
                elif task_type == TaskType.SUBDOMAIN_BRUTEFORCE:
                    status_reason = f"Found {len(result_data['subdomains'])} subdomains for {current_task.payload.get('domain')}"
                else:
                    status_reason = "Interesting results found"
            else:
                status = TaskStatus.OK
                if task_type == TaskType.DOMAIN:
                    status_reason = f"No valid domains found for {current_task.payload.get('domain')}"
                elif task_type == TaskType.DOMAIN_LIST:
                    status_reason = "No valid domains found in list"
                elif task_type == TaskType.SUBDOMAIN_BRUTEFORCE:
                    status_reason = f"No subdomains found for {current_task.payload.get('domain')}"
                else:
                    status_reason = None
        
        except KeyError as e:
            self.log.error(f"Missing required key in task: {e}")
            status = TaskStatus.ERROR
            status_reason = f"Missing required key in task: {e}"
            result_data = {"error": f"Missing required key in task: {e}"}
        
        except ValueError as e:
            self.log.error(f"Invalid value in task: {e}")
            status = TaskStatus.ERROR
            status_reason = f"Invalid value in task: {e}"
            result_data = {"error": f"Invalid value in task: {e}"}
            
        except Exception as e:
            self.log.exception(f"Unexpected error while processing task: {e}")
            status = TaskStatus.ERROR
            status_reason = f"Unexpected error: {e}"
            result_data = {"error": f"Unexpected error: {str(e)}"}
            
        finally:
            # Save task result to database
            self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result_data)
            self.log.info(f"Saved task result with status {status}")

    def process_domain(self, task: Task) -> tuple[list, list]:
        """
        Resolves subdomains for a single domain using puredns.
        Returns a tuple of (valid_domains, wildcard_domains).
        """
        domain = task.payload.get("domain")
        self.log.info(f"Processing single domain task for: {domain}")

        temp_domain_file = None
        output_file = None
        wildcards_file = None
        massdns_file = None
        temp_files = []  # Track all temporary files for cleanup

        # Assume config is accessible via self.config (adjust if needed)
        puredns_path = os.environ.get("PUREDNS_PATH", "puredns")
        resolvers_file = os.environ.get("RESOLVERS_FILE", "resolvers.txt")

        if not os.path.exists(resolvers_file):
            self.log.error(f"Resolvers file not found at {resolvers_file}. Skipping puredns.")
            return [], []

        try:
            # 1. Create temporary input file
            temp_domain_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
            temp_domain_file.write(domain + "\n")
            temp_domain_file.close()
            temp_files.append(temp_domain_file.name)

            # 2. Create temporary output files
            output_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-output.txt")
            output_file.close()
            temp_files.append(output_file.name)
            
            wildcards_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-wildcards.txt")
            wildcards_file.close()
            temp_files.append(wildcards_file.name)
            
            massdns_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-massdns.txt")
            massdns_file.close()
            temp_files.append(massdns_file.name)

            # 3. Execute puredns
            cmd = [
                puredns_path,
                "resolve",
                temp_domain_file.name,
                "--resolvers", resolvers_file,
                "--write", output_file.name,
                "--write-wildcards", wildcards_file.name,
                "--write-massdns", massdns_file.name,
            ]
            self.log.info(f"Running puredns command: {' '.join(cmd)}")

            try:
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=300  # 5 minute timeout
                )
            except subprocess.TimeoutExpired:
                self.log.error(f"Puredns command timed out after 300 seconds for domain {domain}")
                return [], []
            except subprocess.SubprocessError as e:
                self.log.error(f"Subprocess error running puredns for domain {domain}: {e}")
                return [], []

            if process.returncode != 0:
                self.log.error(f"Puredns failed for {domain} with return code {process.returncode}")
                self.log.error(f"Puredns stdout: {process.stdout}")
                self.log.error(f"Puredns stderr: {process.stderr}")
                return [], [] # Stop processing if puredns fails

            self.log.info(f"Puredns completed successfully for {domain}")

            # 5. Read results
            valid_domains_list = self._read_file(output_file.name)
            wildcard_domains_list = self._read_file(wildcards_file.name)

            # 6. Create new task with results
            result_payload = {
                "domain": domain,
                "valid_domains": valid_domains_list,
                "wildcard_domains": wildcard_domains_list,
                "massdns_file": massdns_file.name # Path to massdns output
            }

            try:
                new_task = Task(
                    {
                        "type": TaskType.DOMAIN,
                        "origin": self.identity,
                    },
                    payload=result_payload,
                )
                self.send_task(new_task)
                self.log.info(f"Sent {len(valid_domains_list)} valid domains found for {domain}")
            except Exception as e:
                self.log.error(f"Failed to send result task for domain {domain}: {e}")
                # Continue to return results even if sending task fails
            
            return valid_domains_list, wildcard_domains_list

        except FileNotFoundError as e:
             self.log.error(f"Puredns executable not found at '{puredns_path}' or resolvers file missing. Error: {e}")
             return [], []
        except PermissionError as e:
             self.log.error(f"Permission error during puredns processing for {domain}: {e}")
             return [], []
        except Exception as e:
            self.log.exception(f"An error occurred during puredns processing for {domain}: {e}")
            return [], []
        finally:
            # Cleanup all temporary files
            for file_path in temp_files:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        self.log.debug(f"Removed temporary file: {file_path}")
                except OSError as e:
                    self.log.error(f"Error removing temporary file {file_path}: {e}")

    def process_domain_list(self, task: Task) -> tuple[list, list]:
        """
        Resolves subdomains for a list of domains using puredns.
        Returns a tuple of (valid_domains, wildcard_domains).
        """
        domains = task.payload.get("domains")
        if not isinstance(domains, list) or not domains:
            self.log.warning("Received empty or invalid domain list. Skipping.")
            return [], []

        self.log.info(f"Processing domain list task for {len(domains)} domains.")

        temp_domain_list_file = None
        output_file = None
        wildcards_file = None
        massdns_file = None
        temp_files = []  # Track all temporary files for cleanup

        puredns_path = os.environ.get("PUREDNS_PATH", "puredns")
        resolvers_file = os.environ.get("RESOLVERS_FILE", "resolvers.txt")

        if not os.path.exists(resolvers_file):
            self.log.error(f"Resolvers file not found at {resolvers_file}. Skipping puredns.")
            return [], []

        try:
            # 1. Create temporary input file with list of domains
            temp_domain_list_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
            for domain in domains:
                temp_domain_list_file.write(domain + "\n")
            temp_domain_list_file.close()
            temp_files.append(temp_domain_list_file.name)

            # 2. Create temporary output files
            output_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-output.txt")
            output_file.close()
            temp_files.append(output_file.name)
            
            wildcards_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-wildcards.txt")
            wildcards_file.close()
            temp_files.append(wildcards_file.name)
            
            massdns_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-massdns.txt")
            massdns_file.close()
            temp_files.append(massdns_file.name)

            # 3. Execute puredns
            cmd = [
                puredns_path,
                "resolve",
                temp_domain_list_file.name,
                "--resolvers", resolvers_file,
                "--write", output_file.name,
                "--write-wildcards", wildcards_file.name,
                "--write-massdns", massdns_file.name,
            ]
            self.log.info(f"Running puredns command for list: {' '.join(cmd)}")

            try:
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=600  # 10 minute timeout for lists
                )
            except subprocess.TimeoutExpired:
                self.log.error(f"Puredns command timed out after 600 seconds for domain list")
                return [], []
            except subprocess.SubprocessError as e:
                self.log.error(f"Subprocess error running puredns for domain list: {e}")
                return [], []

            if process.returncode != 0:
                self.log.error(f"Puredns failed for domain list with return code {process.returncode}")
                self.log.error(f"Puredns stdout: {process.stdout}")
                self.log.error(f"Puredns stderr: {process.stderr}")
                return [], [] # Stop processing if puredns fails

            self.log.info(f"Puredns completed successfully for domain list.")

            # 5. Read results
            valid_domains_list = self._read_file(output_file.name)
            wildcard_domains_list = self._read_file(wildcards_file.name)

            # 6. Create new task with results
            result_payload = {
                "domains": domains, # Original list
                "valid_domains": valid_domains_list,
                "wildcard_domains": wildcard_domains_list,
                "massdns_file": massdns_file.name
            }

            try:
                new_task = Task(
                    {
                        "type": TaskType.DOMAIN_LIST, # Send results as DOMAIN_LIST
                        "origin": self.identity,
                    },
                    payload=result_payload,
                )
                self.send_task(new_task)
                self.log.info(f"Sent {len(valid_domains_list)} valid domains found for the list.")
            except Exception as e:
                self.log.error(f"Failed to send result task for domain list: {e}")
                # Continue to return results even if sending task fails
            
            return valid_domains_list, wildcard_domains_list

        except FileNotFoundError as e:
             self.log.error(f"Puredns executable not found at '{puredns_path}' or resolvers file missing. Error: {e}")
             return [], []
        except PermissionError as e:
             self.log.error(f"Permission error during puredns processing for domain list: {e}")
             return [], []
        except Exception as e:
            self.log.exception(f"An error occurred during puredns processing for domain list: {e}")
            return [], []
        finally:
            # Cleanup all temporary files
            for file_path in temp_files:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        self.log.debug(f"Removed temporary file: {file_path}")
                except OSError as e:
                    self.log.error(f"Error removing temporary file {file_path}: {e}")

    def perform_subdomain_bruteforce(self, task: Task) -> tuple[list, list]:
        """
        Performs subdomain bruteforce using puredns.
        Returns a tuple of (subdomains, wildcard_domains).
        """
        payload = task.payload.get("domain")
        if isinstance(payload, dict):
            root_domain = payload.get("domain")
            wordlist_path = payload.get("wordlist_path")
        else:
            root_domain = payload
            wordlist_path = None
        
        if not root_domain:
            self.log.warning("Missing domain for subdomain bruteforce. Skipping.")
            return [], []

        self.log.info(f"Performing subdomain bruteforce task for: {root_domain}")

        # Define default wordlist path (adjust as needed, e.g., from config)
        default_wordlist = os.environ.get("DEFAULT_WORDLIST", "/opt/wordlists/default.txt")

        if wordlist_path and os.path.exists(wordlist_path):
            final_wordlist = wordlist_path
            self.log.info(f"Using provided wordlist: {final_wordlist}")
        elif os.path.exists(default_wordlist):
            final_wordlist = default_wordlist
            self.log.info(f"Using default wordlist: {final_wordlist}")
        else:
            self.log.error(f"No valid wordlist found. Neither provided '{wordlist_path}' nor default '{default_wordlist}' exist. Skipping bruteforce.")
            return [], []

        output_file = None
        wildcards_file = None
        massdns_file = None
        temp_files = []  # Track all temporary files for cleanup

        puredns_path = os.environ.get("PUREDNS_PATH", "puredns")
        resolvers_file = os.environ.get("RESOLVERS_FILE", "resolvers.txt")

        if not os.path.exists(resolvers_file):
            self.log.error(f"Resolvers file not found at {resolvers_file}. Skipping puredns.")
            return [], []

        try:
            # Validate wordlist before proceeding
            if not os.path.exists(final_wordlist):
                self.log.error(f"Wordlist not found at {final_wordlist}. Skipping subdomain bruteforce.")
                return [], []
                
            if os.path.getsize(final_wordlist) == 0:
                self.log.error(f"Wordlist at {final_wordlist} is empty. Skipping subdomain bruteforce.")
                return [], []

            # 2. Create temporary output files
            output_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-bf-output.txt")
            output_file.close()
            temp_files.append(output_file.name)
            
            wildcards_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-bf-wildcards.txt")
            wildcards_file.close()
            temp_files.append(wildcards_file.name)
            
            massdns_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-bf-massdns.txt")
            massdns_file.close()
            temp_files.append(massdns_file.name)

            # 3. Execute puredns bruteforce
            cmd = [
                puredns_path,
                "bruteforce",
                final_wordlist,
                root_domain,
                "--resolvers", resolvers_file,
                "--write", output_file.name,
                "--write-wildcards", wildcards_file.name,
                "--write-massdns", massdns_file.name,
            ]
            self.log.info(f"Running puredns bruteforce command: {' '.join(cmd)}")

            try:
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=1800  # 30 minute timeout for bruteforce
                )
            except subprocess.TimeoutExpired:
                self.log.error(f"Puredns bruteforce command timed out after 1800 seconds for domain {root_domain}")
                return [], []
            except subprocess.SubprocessError as e:
                self.log.error(f"Subprocess error running puredns bruteforce for domain {root_domain}: {e}")
                return [], []

            if process.returncode != 0:
                self.log.error(f"Puredns bruteforce failed for {root_domain} with return code {process.returncode}")
                self.log.error(f"Puredns stdout: {process.stdout}")
                self.log.error(f"Puredns stderr: {process.stderr}")
                return [], [] # Stop processing if puredns fails

            self.log.info(f"Puredns bruteforce completed successfully for {root_domain}.")

            # 5. Read results
            subdomains_list = self._read_file(output_file.name)
            wildcard_domains_list = self._read_file(wildcards_file.name)

            # 6. Create new task with results
            result_payload = {
                "root_domain": root_domain,
                "subdomains": subdomains_list,
                "wildcard_domains": wildcard_domains_list,
                "massdns_file": massdns_file.name
            }

            try:
                new_task = Task(
                    {
                        # Send results as SUBDOMAIN_BRUTEFORCE
                        "type": TaskType.SUBDOMAIN_BRUTEFORCE,
                        "origin": self.identity,
                    },
                    payload=result_payload,
                )
                self.send_task(new_task)
                self.log.info(f"Sent {len(subdomains_list)} subdomains found for {root_domain}.")
            except Exception as e:
                self.log.error(f"Failed to send result task for subdomain bruteforce of {root_domain}: {e}")
                # Continue to return results even if sending task fails
            
            return subdomains_list, wildcard_domains_list

        except FileNotFoundError as e:
             self.log.error(f"Puredns executable not found at '{puredns_path}' or resolvers file missing. Error: {e}")
             return [], []
        except PermissionError as e:
             self.log.error(f"Permission error during puredns bruteforce for {root_domain}: {e}")
             return [], []
        except Exception as e:
            self.log.exception(f"An error occurred during puredns bruteforce for {root_domain}: {e}")
            return [], []
        finally:
            # Cleanup all temporary files
            for file_path in temp_files:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        self.log.debug(f"Removed temporary file: {file_path}")
                except OSError as e:
                    self.log.error(f"Error removing temporary file {file_path}: {e}")

    def _read_file(self, file_path: str) -> list[str]:
        """
        Helper method to read lines from a file.
        Returns list of non-empty lines with whitespace trimmed.
        """
        if not file_path:
            self.log.error("No file path provided for reading")
            return []
            
        try:
            if not os.path.exists(file_path):
                self.log.error(f"File not found: {file_path}")
                return []
                
            if os.path.getsize(file_path) == 0:
                self.log.debug(f"File is empty: {file_path}")
                return []
                
            with open(file_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.log.error(f"File not found: {file_path}")
            return []
        except PermissionError:
            self.log.error(f"Permission denied reading file: {file_path}")
            return []
        except UnicodeDecodeError:
            self.log.error(f"Unicode decode error reading file: {file_path}. Trying with errors='ignore'")
            try:
                with open(file_path, "r", errors="ignore") as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log.error(f"Failed to read file with error handling: {file_path}: {e}")
                return []
        except Exception as e:
            self.log.error(f"Error reading file {file_path}: {e}")
            return []

if __name__ == "__main__":
    PurednsModule().loop()
