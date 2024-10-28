import os
import ctypes
import subprocess


###
    # This script writes, compiles, and loads a simple Linux kernel module.
    # It performs the following steps:
    # 1. Writes a C source file for a test kernel module.
    # 2. Writes a Makefile to compile the kernel module.
    # 3. Compiles the kernel module using the Makefile.
    # 4. Loads the compiled kernel module into the kernel using the finit_module system call.
###

# Constants for system call numbers (Linux-specific)
SYS_finit_module = 313  # On x86_64; this number may vary by architecture

# Load the C library (libc) which contains system calls
libc = ctypes.CDLL("libc.so.6")

# Define finit_module prototype and parameters in ctypes
# int finit_module(int fd, const char *param_values, int flags);
libc.syscall.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
libc.syscall.restype = ctypes.c_int

def write_test_driver():
    """Write the test driver C code to a file."""
    driver_code = """
    #include <linux/module.h>   // Needed by all kernel modules
    #include <linux/kernel.h>   // Needed for KERN_INFO
    #include <linux/init.h>     // Needed for __init and __exit macros

    MODULE_LICENSE("GPL");
    MODULE_AUTHOR("Your Name");
    MODULE_DESCRIPTION("A Simple Test Kernel Module");

    // Function that runs when the module is loaded
    static int __init test_driver_init(void) {
        printk(KERN_INFO "Test Driver Loaded: Hello, Kernel!\\n");
        return 0;  // Return 0 means successful loading
    }

    // Function that runs when the module is unloaded
    static void __exit test_driver_exit(void) {
        printk(KERN_INFO "Test Driver Unloaded: Goodbye, Kernel!\\n");
    }

    // Macros that specify the initialization and cleanup functions
    module_init(test_driver_init);
    module_exit(test_driver_exit);
    """

    # Write to a file
    with open("test_driver.c", "w") as f:
        f.write(driver_code)
    print("Test driver code written to 'test_driver.c'.")

def write_makefile():
    """Write the Makefile to compile the kernel module."""
    makefile_content = """
obj-m += test_driver.o

all:
\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
    """
    # Write the Makefile to the current directory
    with open("Makefile", "w") as f:
        f.write(makefile_content)
    print("Makefile written.")

def compile_driver():
    """Compile the kernel module using the Makefile."""
    try:
        subprocess.run(["make"], check=True)
        print("Kernel module compiled successfully.")
    except subprocess.CalledProcessError:
        print("Failed to compile the kernel module.")
        exit(1)

def load_kernel_module(module_path, params=""):
    """Load the kernel module using the finit_module system call."""
    fd = os.open(module_path, os.O_RDONLY)
    
    if fd < 0:
        print(f"Failed to open module file: {module_path}")
        return
    
    # Make the finit_module system call
    ret = libc.syscall(SYS_finit_module, fd, params.encode('utf-8'), 0)
    
    # If ret == 0, the module was loaded successfully
    if ret == 0:
        print(f"Module {module_path} loaded successfully.")
    else:
        # Handle the case where finit_module fails
        errno = ctypes.get_errno()
        print(f"Failed to load module: {os.strerror(errno)}")

    os.close(fd)

def loadit():
    # Write the driver C code and Makefile
    write_test_driver()
    write_makefile()

    # Compile the kernel module
    compile_driver()

    # Load the kernel module using finit_module system call
    module_path = "./test_driver.ko"  # The compiled kernel module
    load_kernel_module(module_path)