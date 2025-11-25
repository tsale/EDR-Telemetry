// Build & Run Instructions
// ------------------------
// 1. Create a new project:
//      dotnet new console -n ServiceCreator
// 2. Install the Visual C++ Redistributable (x64):
//      https://aka.ms/vs/17/release/vc_redist.x64.exe
// 3. Replace the Program.cs file with this one.
// 4. Publish a self-contained executable (64-bit):
//      dotnet publish -c Release -r win-x64 --self-contained false
// 5. Run the generated .exe from the publish folder (Administrator privileges required).

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

class Program
{
    // SCM + service access flags
    const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    const uint SERVICE_DEMAND_START = 0x00000003;
    const uint SERVICE_ERROR_NORMAL = 0x00000001;
    const uint SERVICE_ALL_ACCESS = 0xF01FF;
    const uint SERVICE_QUERY_STATUS = 0x0004;
    const uint SERVICE_START = 0x0010;
    const uint DELETE = 0x00010000;
    const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateService(
        IntPtr hSCManager,
        string lpServiceName,
        string lpDisplayName,
        uint dwDesiredAccess,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string lpBinaryPathName,
        string lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string lpDependencies,
        string lpServiceStartName,
        string lpPassword);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr OpenService(
        IntPtr hSCManager,
        string lpServiceName,
        uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DeleteService(IntPtr hService);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool StartService(IntPtr hService, int dwNumServiceArgs, IntPtr lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ChangeServiceConfig(
        IntPtr hService,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string lpBinaryPathName,
        string lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string lpDependencies,
        string lpServiceStartName,
        string lpPassword,
        string lpDisplayName);

    static void Main(string[] args)
    {
        if (!IsAdministrator())
        {
            Console.WriteLine("You must run this program as Administrator to manage services.");
            return;
        }

        if (args.Length == 0)
        {
            Console.WriteLine("Usage: ServiceCreator install|start|modify|uninstall");
            return;
        }

        string serviceName = "TestCmdNotepadService";
        string displayName = "Test Cmd Notepad Service";

        switch (args[0].ToLowerInvariant())
        {
            case "install":
                Install(serviceName, displayName);
                break;
            case "start":
                Start(serviceName);
                break;
            case "modify":
                Modify(serviceName);
                break;
            case "uninstall":
                Uninstall(serviceName);
                break;
            default:
                Console.WriteLine("Usage: ServiceCreator install|start|modify|uninstall");
                break;
        }
    }

    static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    static void Install(string serviceName, string displayName)
    {
        // Initial test binary: cmd.exe /c notepad.exe
        string binPath = "\"C:\\Windows\\System32\\cmd.exe\" /c notepad.exe";

        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");

        try
        {
            IntPtr svc = CreateService(
                scm,
                serviceName,
                displayName,
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                binPath,
                null,
                IntPtr.Zero,
                null,
                null,
                null);

            if (svc == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateService failed");

            CloseServiceHandle(svc);
            Console.WriteLine("Service installed.");
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    static void Start(string serviceName)
    {
        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");

        try
        {
            IntPtr svc = OpenService(scm, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
            if (svc == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenService failed");

            try
            {
                if (!StartService(svc, 0, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "StartService failed");

                Console.WriteLine("Service start requested.");
            }
            finally
            {
                CloseServiceHandle(svc);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    static void Modify(string serviceName)
    {
        // New test binary after modification: cmd.exe /c calc.exe
        string newBinPath = "\"C:\\Windows\\System32\\cmd.exe\" /c calc.exe";

        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");

        try
        {
            IntPtr svc = OpenService(scm, serviceName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenService failed");

            try
            {
                bool ok = ChangeServiceConfig(
                    svc,
                    SERVICE_NO_CHANGE,     // keep type
                    SERVICE_NO_CHANGE,     // keep start type
                    SERVICE_NO_CHANGE,     // keep error control
                    newBinPath,            // update binary path
                    null,
                    IntPtr.Zero,
                    null,
                    null,
                    null,
                    null);

                if (!ok)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ChangeServiceConfig failed");

                Console.WriteLine("Service modified successfully.");
            }
            finally
            {
                CloseServiceHandle(svc);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    static void Uninstall(string serviceName)
    {
        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");

        try
        {
            IntPtr svc = OpenService(scm, serviceName, DELETE);
            if (svc == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenService failed");

            try
            {
                if (!DeleteService(svc))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "DeleteService failed");

                Console.WriteLine("Service uninstalled.");
            }
            finally
            {
                CloseServiceHandle(svc);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }
}