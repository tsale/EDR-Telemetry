import dbus
import os
import libuser
import sched
import sys
import time
import socket
import signal
import subprocess
import socket
import csv
import traceback
from ctypes import CDLL
from complex.driver_load import loadit
from complex.process_tampering import begin_tamper
from complex.scheduled_task import run_task
from complex.process_hijack_demo import start_hijacking


scheduler = sched.scheduler(time.time, time.sleep)

class NetworkSocketManager:
    """
    The `network_listen` method is intended to create a standard listening socket for handling incoming TCP 
    connections, while the `network_raw_socket` method creates a raw socket bound to a network interface.
    """

    @staticmethod
    def network_listen():
        """
        Creates a listening socket that binds to a specified IP and port.
        """
        try:
            listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_socket.bind(('0.0.0.0', 12345))  # Bind to all interfaces on port 12345
            listen_socket.listen(5)
            print("Listening on 0.0.0.0:12345...")
        except socket.error as e:
            print(f"Error in NetworkListen: {e}")
        finally:
            listen_socket.close()

    @staticmethod
    def network_raw_socket():
        """
        Creates a raw socket that binds to an existing network interface.
        """
        try:
            # Automatically find an available network interface
            def get_interface():
                interfaces = os.listdir('/sys/class/net/')
                for interface in interfaces:
                    if interface != 'lo':  # Skip the loopback interface
                        return interface
                raise Exception("No valid network interfaces found.")

            interface = get_interface()
            raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            raw_socket.bind((interface, 0))  # Bind to the automatically found network interface
            print(f"Raw socket bound to {interface}...")
        except socket.error as e:
            print(f"Error in NetworkRawSocket: {e}")
        except Exception as e:
            print(f"Error finding network interface: {e}")
        finally:
            raw_socket.close()
    
    @staticmethod
    def network_connect():
        # Function to trigger a network connection
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
    device = '/dev/sda'  # Using '/dev/sda' as the main hard drive device
    num_bytes = 512       # Number of bytes to read
    offset = 0            # Offset from the beginning of the device

    try:
        with open(device, 'rb') as f:  # Open the device in read-only mode
            data = f.read(1024)  # Read the first 1024 bytes for demonstration
            print(data)
    except PermissionError:
        print("Permission denied: You need to run this script with elevated privileges.")
    except FileNotFoundError:
        print(f"Device {device} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Dictionary mapping event names to functions
event_functions = {
    'FileCreated': test_file_operations,
    'FileModified': test_file_operations,
    'FileDelete': test_file_operations,
    'DnsQuery': dns_query,
    'ProcessTerminate': process_terminate,
    'ImageLoad': image_load,
    'ProcessAccess': start_hijacking,
    'NetworkConnect': network_connect,
    'ServiceStartStop': start_and_stop_service,
    'RawAccessRead': raw_access_read,
    'LoadDriver': loadit,
    'TamperProcess': begin_tamper,
    'ScheduledTask': run_task,
    'UserAccountEvents': UserAccountManager().run,
    'NetworkListen': NetworkSocketManager.network_listen,
    'NetworkRawSocket': NetworkSocketManager.network_raw_socket,
    'NetworkConnect': NetworkSocketManager.network_connect
}

def log_to_csv(function_name, output, error=None):
    with open('function_output_log.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([function_name, output, error])

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
        try:
            output = event_functions[event]()
            log_to_csv(event, "Success")
        except Exception as e:
            error_message = traceback.format_exc()
            log_to_csv(event, "", error_message)
            print(f"Error running {event}: {e}")
            continue  # Continue to the next function even if there is an error

if __name__ == "__main__":
    # Initialize CSV file with headers
    with open('function_output_log.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Function", "Output", "Error"])
    main()

