#!/usr/bin/env python3
import argparse
import os
import subprocess
from datetime import datetime
import time
import signal

# Set up argument parser
parser = argparse.ArgumentParser(description="Run Rowhammer Attack Script")
parser.add_argument("--core", default="6", help="Specify the CPU core to use (default: %(default)s)")

# Parse arguments
args = parser.parse_args()

# Assign arguments to variables
CORE = args.core

# Commands
task_command = f"/usr/bin/sudo taskset -c {CORE} ./rowhammer_corruption"

print (task_command)


# Function to print the task command only
def print_task_command():
    print(task_command)

def terminate_process(process):
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except ProcessLookupError:
        print("Process already terminated.")



def run_task(log_file_path, task_command=task_command):

    try:
        while True:
            # Execute command and capture stdout and stderr
            with open(log_file_path, 'a') as log_file:
                main_process = subprocess.Popen(task_command, shell=True, stdout=log_file, stderr=log_file, preexec_fn=os.setsid)

                # If "sudo: a terminal is required to read the password" occurs, the script will be interrupted

                # open log file and check
                with open(log_file_path, 'r') as log_file:
                    log_file.seek(0, os.SEEK_END)
                    while True:
                        line = log_file.readline()
                        if not line:
                            time.sleep(1)
                            if main_process.poll() is not None:
                                print("Script finished.")
                            continue
                        print(line, end='')
                        if "sudo: a terminal is required to read the password" in line:
                            print("Script interrupted, terminating subprocesses.")
                            terminate_process(main_process)

                            # remove sudo from command and try again
                            task_command = task_command.replace("/usr/bin/sudo", "")

                            run_task(log_file_path, task_command=task_command)

    except KeyboardInterrupt:
        print("Script interrupted, terminating subprocesses.")
        if main_process:
            terminate_process(main_process)
    except subprocess.CalledProcessError as e:
        print(f"Command '{task_command}' returned non-zero exit status {e.returncode}.")




# Run the script
if __name__ == "__main__":
    # Create logs folder if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Get the current date and time for the log file name
    current_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    # Log file path
    log_file_path = f'logs/rowhammer_log_{current_time}.txt'
    
    run_task(log_file_path)
