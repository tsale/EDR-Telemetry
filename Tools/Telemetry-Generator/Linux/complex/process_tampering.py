import os
import subprocess
import time
import struct

# C code for the test program
C_CODE = """
#include <stdio.h>
#include <unistd.h>

int target_value = 0x12345678;

int main() {
    printf("Test process started. PID: %d\\n", getpid());
    fflush(stdout);  // Ensure the output is immediately flushed
    printf("Target value is initially: 0x%x\\n", target_value);
    fflush(stdout);  // Ensure the output is immediately flushed

    // Infinite loop to keep the process running
    while (1) {
        sleep(1);  // Sleep to avoid high CPU usage
    }

    return 0;
}
"""

def compile_and_run_test_program():
    """Write, compile, and run the C test program."""
    c_file = "test_program.c"
    executable = "./test_program"
    
    try:
        # Write the C code to a file
        with open(c_file, "w") as f:
            f.write(C_CODE)
        
        # Compile the C program
        compile_cmd = ["gcc", "-o", executable, c_file]
        subprocess.run(compile_cmd, check=True)
        print("C test program compiled successfully.")
        
        # Run the compiled test program asynchronously
        process = subprocess.Popen([executable], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed: {e}")
        raise Exception("Failed to compile the test program")  # Raise an exception instead

    # Capture the PID from the test program's output
    pid = None
    while True:
        line = process.stdout.readline().strip()
        print(line)  # Print output for debugging
        if "PID" in line:
            pid = int(line.split("PID: ")[1])
            break
    
    if not pid:
        raise Exception("Failed to get PID from the test program.")
    
    return pid, process

def read_memory_from_proc(pid, address, size=4):
    """Read memory directly from /proc/<pid>/mem."""
    mem_path = f"/proc/{pid}/mem"
    try:
        with open(mem_path, 'rb') as mem_file:
            mem_file.seek(address)
            return mem_file.read(size)
    except Exception as e:
        print(f"Error reading memory from {hex(address)}: {e}")
        return None

def write_memory_to_proc(pid, address, value):
    """Write memory directly to /proc/<pid>/mem."""
    mem_path = f"/proc/{pid}/mem"
    value_bytes = struct.pack("I", value)  # Convert integer value to bytes
    try:
        with open(mem_path, 'wb') as mem_file:
            mem_file.seek(address)
            mem_file.write(value_bytes)
            print(f"Successfully wrote {hex(value)} to {hex(address)}")
    except Exception as e:
        print(f"Error writing memory to {hex(address)}: {e}")

def find_variable_address(pid, target_value):
    """Search for the target value in the process's memory."""
    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"
    target_value_bytes = struct.pack("I", target_value)  # Pack target_value as bytes

    try:
        with open(maps_path, 'r') as maps_file, open(mem_path, 'rb', 0) as mem_file:
            for line in maps_file:
                if 'rw-p' in line:  # Look for writable memory segment
                    address_range = line.split(' ')[0]
                    start_address, end_address = [int(addr, 16) for addr in address_range.split('-')]
                    print(f"Checking memory segment: {hex(start_address)} - {hex(end_address)}")

                    # Search for the target value in the memory segment
                    mem_file.seek(start_address)
                    memory = mem_file.read(end_address - start_address)
                    address_offset = memory.find(target_value_bytes)
                    if address_offset != -1:
                        return start_address + address_offset  # Return the address where target_value is found
    except FileNotFoundError:
        raise Exception(f"Could not open memory maps or memory file for process {pid}")
    return None

def tamper_process(pid, target_value):
    """Tamper with process memory using /proc/<pid>/mem."""
    try:
        # Step 1: Find the memory address of the target variable
        address = find_variable_address(pid, target_value)
        if address is None:
            raise Exception("Could not find the target value in memory.")
        print(f"Found target value at address: {hex(address)}")

        # Step 2: Read the original value from memory
        original_value = read_memory_from_proc(pid, address)
        if original_value is not None:
            original_value = struct.unpack("I", original_value)[0]  # Convert bytes to integer
            print(f"Original value at {hex(address)}: {hex(original_value)}")
        
        # Step 3: Write a new value to the memory
        new_value = 0xDEADBEEF
        write_memory_to_proc(pid, address, new_value)
        
        # Step 4: Verify the tampering
        tampered_value = read_memory_from_proc(pid, address)
        if tampered_value is not None:
            tampered_value = struct.unpack("I", tampered_value)[0]
            print(f"New value at {hex(address)}: {hex(tampered_value)}")
        
    except Exception as e:
        print(f"Error: {e}")

def cleanup(process):
    """Terminate the test program and clean up."""
    process.terminate()  # Kill the running test process
    process.wait()  # Wait for process termination
    print("Test process terminated.")

def begin_tamper():
    """Main function to demonstrate process tampering."""
    try:
        # Step 1: Compile and run the C test program asynchronously
        pid, process = compile_and_run_test_program()
        print(f"Test program running with PID: {pid}")
        
        # Step 2: Tamper with the process's memory
        target_value = 0x12345678  # The known value we want to tamper with
        tamper_process(pid, target_value)
        
        # Step 3: Clean up and terminate the test program
        cleanup(process)
        
        return "Process tampering completed successfully."
    except Exception as e:
        print(f"Error during process tampering: {e}")
        raise
