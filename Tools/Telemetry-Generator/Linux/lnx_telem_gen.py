import dbus
import os
import libuser
import random
import sched
import sys
import time
import socket
from ctypes import CDLL
import psutil
import signal
import ctypes
import subprocess
from complex.driver_load import loadit
from complex.process_tampering import begin_tamper
from complex.scheduled_task import run_task
import pwd
import spwd
import crypt


scheduler = sched.scheduler(time.time, time.sleep)

class RemoteLibraryInjector:
    def __init__(self, pid=None):
        self.libc = ctypes.CDLL("libc.so.6")
        self.pid = pid if pid else self.get_random_pid()

    def get_random_pid(self):
        # Get a list of all PIDs from /proc
        pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]

        if not pids:
            raise Exception("No running processes found.")

        # Select a random PID
        return int(random.choice(pids))

    def create_shared_library(self):
        # C code for the shared library
        c_code = """
        #include <stdio.h>

        __attribute__((constructor))
        void init() {
            printf("Hello from injected library!\\n");
        }
        """

        # Write the C code to a file
        with open("inject.c", "w") as f:
            f.write(c_code)

        # Compile the C code into a shared library
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", "inject.so", "inject.c"], check=True)

        print("Shared library 'inject.so' created successfully.")

    def attach_to_process(self):
        PTRACE_ATTACH = 16
        if self.libc.ptrace(PTRACE_ATTACH, self.pid, None, None) == -1:
            raise Exception(f"Failed to attach to process {self.pid}")
        # Wait for the process to stop
        os.waitpid(self.pid, 0)

    def detach_from_process(self):
        PTRACE_DETACH = 17
        try:
            if self.libc.ptrace(PTRACE_DETACH, self.pid, None, None) == -1:
                # Silently fail if detach fails
                pass
        except Exception:
            pass

    def inject_library(self, lib_path):
        RTLD_NOW = 2
        # Load the shared library into the target process using dlopen
        dlopen = self.libc.dlopen
        dlopen.argtypes = [ctypes.c_char_p, ctypes.c_int]
        dlopen.restype = ctypes.c_void_p

        # We are assuming the library path is valid
        lib_path_bytes = lib_path.encode('utf-8')

        # Call dlopen in the target process to load the shared library
        handle = dlopen(lib_path_bytes, RTLD_NOW)
        if handle is None:
            raise Exception(f"Failed to inject library {lib_path}")

        print(f"Library {lib_path} injected successfully with handle {handle}")

    def inject_shared_library(self):
        PTRACE_CONT = 7
        try:
            # Step 1: Create and compile the shared library
            self.create_shared_library()

            # Step 2: Attach to the process
            self.attach_to_process()

            # Step 3: Inject the shared library into the target process
            self.inject_library("./inject.so")

            # Step 4: Continue the process after injection
            self.libc.ptrace(PTRACE_CONT, self.pid, None, None)

        finally:
            # Step 5: Detach from the process
            self.detach_from_process()

        print(f"Injected into process with PID: {self.pid}")

class UserAccountManager:
    """
    UserAccountManager is a class responsible for managing user accounts on a Linux system.
    It provides methods to create, modify, and delete user accounts using the libuser library.
    Additionally, it sets up the necessary libuser configuration and installs the required packages.
    """
    def __init__(self):
        self.username = "testuser"
        self.password = "password123"
        self.new_password = "newpassword123"
        self.setup_libuser()

    def setup_libuser(self):
        try:
            # Install libuser development package
            subprocess.run(["sudo", "apt-get", "install", "-y", "python3-libuser"], check=True)

            # Create the libuser configuration file
            libuser_conf = "/etc/libuser.conf"
            if not os.path.exists(libuser_conf):
                with open(libuser_conf, "w") as f:
                    f.write("[defaults]\n")
                    f.write("LU_DEFAULT_USERGROUPS = true\n")
                    f.write("LU_DEFAULT_HOME = /home\n")
                    f.write("LU_DEFAULT_SHELL = /bin/bash\n")
            print("libuser setup completed successfully.")
        except Exception as e:
            print(f"Failed to set up libuser: {e}")

    def create_user(self):
        try:
            # Initialize the libuser context
            ctx = libuser.admin()

            # Create a new user
            user = ctx.initUser(self.username)
            user.set("password", self.password)
            user.set("home", f"/home/{self.username}")
            user.set("shell", "/bin/bash")

            # Add the user to the system
            if not ctx.addUser(user):
                raise Exception("Failed to create user")

            print(f"User '{self.username}' created successfully.")
        except Exception as e:
            print(f"Failed to create user '{self.username}': {e}")

    def modify_user(self):
        try:
            # Initialize the libuser context
            ctx = libuser.admin()

            # Get the existing user
            user = ctx.lookupUserByName(self.username)
            if not user:
                raise Exception(f"User '{self.username}' does not exist")

            # Modify the user's password
            user.set("password", self.new_password)

            # Update the user in the system
            if not ctx.modifyUser(user):
                raise Exception("Failed to modify user")

            print(f"User '{self.username}' modified successfully.")
        except Exception as e:
            print(f"Failed to modify user '{self.username}': {e}")

    def delete_user(self):
        try:
            # Initialize the libuser context
            ctx = libuser.admin()

            # Get the existing user
            user = ctx.lookupUserByName(self.username)
            if not user:
                raise Exception(f"User '{self.username}' does not exist")

            # Delete the user from the system
            if not ctx.deleteUser(user):
                raise Exception("Failed to delete user")

            print(f"User '{self.username}' deleted successfully.")
        except Exception as e:
            print(f"Failed to delete user '{self.username}': {e}")

    def run(self):
        self.create_user()
        time.sleep(2)
        self.modify_user()
        time.sleep(2)
        self.delete_user()

# Function to start and stop the service (cron) using system calls (DBus API)
def start_and_stop_service():
    service_name = "cron"
    start_delay = 0  # Start immediately
    stop_delay = 10  # Stop after 10 seconds

    def start_service():
        bus = dbus.SystemBus()
        systemd = bus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
        manager = dbus.Interface(systemd, 'org.freedesktop.systemd1.Manager')
        try:
            manager.StartUnit(f"{service_name}.service", 'replace')
            print(f"{service_name} service started successfully (system API call).")
        except dbus.DBusException as e:
            print(f"Failed to start {service_name}: {e}")

    def stop_service():
        bus = dbus.SystemBus()
        systemd = bus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
        manager = dbus.Interface(systemd, 'org.freedesktop.systemd1.Manager')
        try:
            manager.StopUnit(f"{service_name}.service", 'replace')
            print(f"{service_name} service stopped successfully (system API call).")
        except dbus.DBusException as e:
            print(f"Failed to stop {service_name}: {e}")

    # Schedule service start and stop
    scheduler.enter(start_delay, 1, start_service)
    scheduler.enter(stop_delay, 1, stop_service)
    scheduler.run()

# Function for file creation, modification, and deletion
def test_file_operations():
    file_name = "test_file.txt"

    def create_file():
        with open(file_name, "w") as f:
            f.write("This is a test file.")
        print(f"File '{file_name}' created.")

    def modify_file():
        if os.path.exists(file_name):
            with open(file_name, "a") as f:
                f.write("\nFile has been modified.")
            print(f"File '{file_name}' modified.")
        else:
            print(f"File '{file_name}' not found for modification.")

    def delete_file():
        if os.path.exists(file_name):
            os.remove(file_name)
            print(f"File '{file_name}' deleted.")
        else:
            print(f"File '{file_name}' not found for deletion.")

    # Perform file operations sequentially
    create_file()
    time.sleep(2)
    modify_file()
    time.sleep(2)
    delete_file()

# Function to perform a DNS query
def dns_query():
    domain = 'www.google.com'
    try:
        ip = socket.gethostbyname(domain)
        print(f"DNS query for {domain} returned IP: {ip}")
    except socket.error as e:
        print(f"DNS query failed: {e}")

# Function to create and terminate a process
def process_terminate():
    pid = os.fork()
    if pid == 0:
        # Child process
        time.sleep(30)  # Simulate work
        os._exit(0)
    else:
        # Parent process
        print(f"Started child process with PID: {pid}")
        time.sleep(5)
        os.kill(pid, signal.SIGTERM)
        print(f"Terminated child process with PID: {pid}")

# Function to load a shared library (image)
def image_load():
    libc = CDLL('libc.so.6')
    print("Loaded shared library 'libc.so.6' into process.")

# Function to access another process's information
def process_access():
    current_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['pid'] != current_pid:
            print(f"Accessed process info: PID {proc.info['pid']}, Name {proc.info['name']}")
            break

# Function to trigger a network connection
def network_connect():
    try:
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Google's IP address and port 80 (HTTP)
        server_address = ('google.com', 80)
        print(f"Attempting to connect to {server_address[0]} on port {server_address[1]}...")
        sock.connect(server_address)
        print("Network connection established.")
        # Close the socket
        sock.close()
    except socket.error as e:
        print(f"Network connection failed: {e}")

# Function to perform raw access read
def raw_access_read():
    # Replace with a safer device for testing
    device = '/dev/zero'  # Using '/dev/zero' as a safe test device
    num_bytes = 512       # Number of bytes to read
    offset = 0            # Offset from the beginning of the device

    try:
        # Open the device for reading as a raw device
        with open(device, 'rb') as f:
            # Seek to the desired offset
            f.seek(offset)
            # Read the specified number of bytes
            data = f.read(num_bytes)
            # Print the raw data in hexadecimal format
            print('Raw data read from device:')
            print(' '.join(f'{byte:02x}' for byte in data))
    except PermissionError:
        print(f"Permission denied: Unable to read from {device}. Try running with elevated privileges.")
    except Exception as e:
        print(f"An error occurred while reading from {device}: {e}")

# Dictionary mapping event names to functions
event_functions = {
    'FileCreated': test_file_operations,
    'FileModified': test_file_operations,
    'FileDelete': test_file_operations,
    'DnsQuery': dns_query,
    'ProcessTerminate': process_terminate,
    'ImageLoad': image_load,
    'ProcessAccess': process_access,
    'NetworkConnect': network_connect,
    'ServiceStartStop': start_and_stop_service,
    'RawAccessRead': raw_access_read,
    'CreateRemoteThread': RemoteLibraryInjector().inject_shared_library,
    'LoadDriver': loadit,
    'TamperProcess': begin_tamper,
    'ScheduledTask': run_task,
    'UserAccountEvents': UserAccountManager().run
}

def main():
    # Check for command-line arguments
    if len(sys.argv) > 1:
        # User has specified which events to run
        selected_events = sys.argv[1:]
    else:
        # No arguments provided; run all events
        selected_events = list(event_functions.keys())

    # Remove duplicates and invalid event names
    selected_events = set(selected_events).intersection(event_functions.keys())

    if not selected_events:
        print("No valid events specified.")
        print("Available events:", ', '.join(event_functions.keys()))
        sys.exit(1)

    for event in selected_events:
        print(f"\n--- Running {event} ---")
        event_functions[event]()

if __name__ == "__main__":
    main()
