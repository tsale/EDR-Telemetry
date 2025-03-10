import os
import pwd
import time
import subprocess

CRON_PATH = '/var/spool/cron/crontabs'

def get_username():
    """Get the current username."""
    return pwd.getpwuid(os.getuid()).pw_name

def create_cron_job(command, schedule="* * * * *"):
    """Create a cron job for the current user."""
    try:
        username = get_username()
        cron_file_path = os.path.join(CRON_PATH, username)
        
        # Ensure the cron directory exists
        if not os.path.exists(CRON_PATH):
            raise Exception(f"Cron path {CRON_PATH} does not exist.")
        
        # Build the cron job entry
        cron_job = f"{schedule} {command}\n"
        
        # Write the cron job directly into the user's crontab file
        with open(cron_file_path, 'a') as cron_file:
            cron_file.write(cron_job)
            print(f"Cron job added: {cron_job.strip()}")
        
        # Change permissions of the crontab file to ensure it is correct
        os.chmod(cron_file_path, 0o600)  # User read-write, no other permissions

        # Reload cron daemon to apply the changes
        subprocess.run(['service', 'cron', 'reload'], check=True)
        print(f"Cron daemon reloaded successfully.")
    
    except Exception as e:
        print(f"Error creating cron job: {e}")
        raise Exception("Failed to create cron job")  # Raise an exception

def remove_cron_job(command):
    """Remove the specified cron job for the current user."""
    try:
        username = get_username()
        cron_file_path = os.path.join(CRON_PATH, username)
        
        if not os.path.exists(cron_file_path):
            raise Exception(f"Cron file {cron_file_path} does not exist.")
        
        # Read the current cron file and filter out the specific job
        with open(cron_file_path, 'r') as cron_file:
            lines = cron_file.readlines()
        
        # Filter out the line containing the command
        new_lines = [line for line in lines if command not in line]
        
        # Write the modified cron file back
        with open(cron_file_path, 'w') as cron_file:
            cron_file.writelines(new_lines)
            print(f"Removed cron job: {command}")
        
        # Reload cron daemon to apply the changes
        subprocess.run(['service', 'cron', 'reload'], check=True)
        print(f"Cron daemon reloaded after cleanup.")
    
    except Exception as e:
        print(f"Error removing cron job: {e}")
        raise Exception("Failed to remove cron job")  # Raise an exception

def run_task():
    """Main function to create a scheduled task using cron, and then clean it up."""
    # Define the command to be scheduled and the schedule (every minute by default)
    command = '/usr/bin/echo "Hello from cron task!"'
    schedule = "* * * * *"  # Runs every minute; modify as needed
    
    # Step 1: Create the cron job
    create_cron_job(command, schedule)
    
    # Step 2: Wait for a short while (e.g., 1 minute) to allow the job to run once
    print("Waiting for the cron job to run once...")
    time.sleep(10)  # Sleep for 10 seconds to allow the cron job to run
    
    # Step 3: Remove the cron job
    remove_cron_job(command)
    
    return "Scheduled task created and removed successfully."
