function Invoke-MemoryDump
{
<#
.SYNOPSIS
This is a simple PowerShell script to dump a process's memory.

.DESCRIPTION
This is a simple PowerShell script to dump a process's memory.

This function allows an elevated user to dump a process's memory using MiniDumpWriteDump.

.PARAMETER ProcID
Process ID of the process whose memory you wish to dump.

.EXAMPLE

PS > Invoke-MemoryDump -ProcID 1234

Use above command to dump memory for process ID 1234 to out.dmp in the current working directory.

.EXAMPLE

PS > Invoke-MemoryDump -ProcID 1234 -OutputPath .\lsass_1234.dmp

Use above command to dump memory for process ID 1234 to a file in the current directory called lsass_1234.dmp.

.LINK
https://github.com/reigningshells

#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[int]$ProcID,

		[Parameter(Mandatory = $False)]
		[String]$OutputPath = "out.dmp"
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	public static class Dbghelp
	{

		[DllImport("dbghelp.dll", SetLastError = true)]
        	public static extern bool MiniDumpWriteDump(IntPtr hProcess, 
			uint processId, 
			IntPtr hFile, 
			int dumpType, 
			IntPtr expParam, 
			IntPtr userStreamParam, 
			IntPtr callbackParam);
	}

"@

	# Must be run from high or system integrity process
	if(($(whoami /groups) -like "*S-1-16-12288*").length -eq 0 -and 
	   ($(whoami /groups) -like "*S-1-16-16384*").length -eq 0) {
		Write-Output "`n[!] Must be run elevated!`n"
		Return
	}
	
	# Check PID
	$IsValidPID = (Get-Process | Select -Expand Id) -Contains $ProcID
	if (!$IsValidPID) {
		Write-Output "`n[!] The specified PID does not exist!`n"
		Return
	}

	# Get process handle
	$procHandle = (Get-Process -Id $ProcID).Handle
	Write-Verbose "`n[+] Process handle: $ProcHandle"

	# Get handle for minidump outfile
	try {
		$fs = [System.IO.File]::Create($OutputPath)
	} catch {
		Write-Output "`n[!] Error getting handle on $OutputPath!`n"
		Return
	}

	$MiniDumpSuccessful = [Dbghelp]::MiniDumpWriteDump($procHandle, 
		$ProcID, 
		$fs.Handle, 
		0x00000002, 
		[IntPtr]::Zero, 
		[IntPtr]::Zero, 
		[IntPtr]::Zero)

	$fs.Close()

	if (!$MiniDumpSuccessful) {
		Write-Output "`n[!] Process dump failed!"
		Remove-Item $fs.Name
	} else {
		Write-Verbose "`n[+] Process dump success!"
	}

}
