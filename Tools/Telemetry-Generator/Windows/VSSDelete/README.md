# VssDeletePOC

This is a simple proof-of-concept for deleting the first available Volume Shadow Copy Service (VSS) snapshot on Windows.  
It uses the [AlphaVSS](https://github.com/alphaleonis/AlphaVSS) library.

## Setup & Run

1. Create a new console project:
   ```bash
   dotnet new console -n VssDeletePOC
   cd VssDeletePOC
2. Add the dependency:
   ```bash
   dotnet add package AlphaVSS
   cd VssDeletePOC
   ```
   If you see an error about no versions available, run:
   ```bash
   dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org
   ```
3. Replace the content of `Program.cs` with the content of [Program.cs](Program.cs).
4. Run the program:
   ```bash
   dotnet run
   ```

## Build & Run as Executable

1. Install the [Visual C++ Redistributable (x64)](https://aka.ms/vs/17/release/vc_redist.x64.exe).
2. Publish a self-contained executable (64-bit):

   ```bash
   dotnet publish -c Release -r win-x64 --self-contained true
   ```
3. Run the generated `.exe` (requires **Administrator** privileges).

---

## Creating a VSS Snapshot

If you don't have a VSS snapshot already, on a Windows server, you can create one using the following command:
```bash
vssadmin create shadow /for=C:
```
Replace `C:` with the drive letter you want to snapshot.

You can verify that the snapshot was created by running:
```bash
vssadmin list shadows
```
