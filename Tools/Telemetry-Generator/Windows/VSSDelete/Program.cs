// Program.cs
//
// Before you begin compiling, follow the steps below:
// ------------------------
// 1. Create a new project:
//     dotnet new console -n VssDeletePOC
//
// 2. Navigate to that directory:
//     cd VssDeletePOC
//
// 3. Add the dependency:
//     dotnet add package AlphaVSS
// -- If you get an error for no versions available for package AlphaVSS, run this:
// dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org
//
// 4. Run the program:
//     dotnet run
// _____________________________________________
//
// Build & Run Instructions
// ------------------------
// 1. Install the Visual C++ Redistributable (x64):
//      https://aka.ms/vs/17/release/vc_redist.x64.exe
//
// 2. Publish a self-contained executable (64-bit):
//      dotnet publish -c Release -r win-x64 --self-contained true
//
// 3. Run the generated .exe from the publish folder (Administrator privileges required).

using System;
using System.Linq;
using Alphaleonis.Win32.Vss;

class DeleteFirstSnapshot
{
    static void Main()
    {
        try
        {
            var factory = VssFactoryProvider.Default.GetVssFactory();

            using (IVssBackupComponents backup = factory.CreateVssBackupComponents())
            {
                backup.InitializeForBackup(null);
                backup.SetContext(VssSnapshotContext.All);

                VssSnapshotProperties first = backup.QuerySnapshots().FirstOrDefault();

                if (first != null)
                {
                    Console.WriteLine("Deleting snapshot: " + first.SnapshotId);
                    backup.DeleteSnapshot(first.SnapshotId, false);
                    Console.WriteLine("Snapshot deleted.");
                }
                else
                {
                    Console.WriteLine("No snapshots found.");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("VSS operation failed.");
            Console.WriteLine("Message : " + ex.Message);
            Console.WriteLine("HResult : 0x" + ex.HResult.ToString("X"));
            Console.WriteLine("Stack   : " + ex.StackTrace);
        }
    }
}