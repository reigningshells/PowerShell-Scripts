function Invoke-ProcessFromParent 
{
<#
.SYNOPSIS
This is a simple PowerShell cmdlet to spawn a process with a specific parent PID.

.DESCRIPTION
This is a simple PowerShell cmdlet to spawn a process with a specific parent PID.

Most of this came from https://github.com/decoder-it/psgetsystem but I had an issue
with it on PowersShell version 2 so created this in response to those issues.

.PARAMETER ParentId
Process ID of the parent you wish your process to have.

.PARAMETER Command
Command you wish to run.

.PARAMETER CommandArgs
Command arguments you wish to pass to the command.

.EXAMPLE

PS > Invoke-ProcessFromParent -ParentId 1234 -Command "C:\windows\system32\cmd.exe"

Use above command to spawn a process, in this case cmd.exe, with parent process ID of 1234, without any arguments.

.EXAMPLE

PS > Invoke-ProcessFromParent -ParentId 1234 -Command "C:\windows\system32\cmd.exe" -CommandArguments "/k whoami"

Use above command to spawn a process, in this case cmd.exe, with parent process ID of 1234, with arguments.

.LINK
https://github.com/reigningshells

#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[int]$ParentId,

		[Parameter(Mandatory = $True)]
		[String]$Command,

		[Parameter(Mandatory = $False)]
		[String]$CommandArgs = $null
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFOEX
	{
		public STARTUPINFO StartupInfo;
		public IntPtr lpAttributeList;
	}

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFO
	{
		public Int32 cb;
		public string lpReserved;
		public string lpDesktop;
		public string lpTitle;
		public Int32 dwX;
		public Int32 dwY;
		public Int32 dwXSize;
		public Int32 dwYSize;
		public Int32 dwXCountChars;
		public Int32 dwYCountChars;
		public Int32 dwFillAttribute;
		public Int32 dwFlags;
		public Int16 wShowWindow;
		public Int16 cbReserved2;
		public IntPtr lpReserved2;
		public IntPtr hStdInput;
		public IntPtr hStdOutput;
		public IntPtr hStdError;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess;
		public IntPtr hThread;
		public int dwProcessId;
		public int dwThreadId;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES
	{
		public int nLength;
		public IntPtr lpSecurityDescriptor;
		public int bInheritHandle;
	}

	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern uint GetLastError();
    
		[DllImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool CreateProcess(
        		string lpApplicationName,
			string lpCommandLine,
			ref SECURITY_ATTRIBUTES lpProcessAttributes,
			ref SECURITY_ATTRIBUTES lpThreadAttributes,
			bool bInheritHandles,
			uint dwCreationFlags,
			IntPtr lpEnvironment,
			string lpCurrentDirectory,
			[In] ref STARTUPINFOEX lpStartupInfo,
			out PROCESS_INFORMATION lpProcessInformation);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool UpdateProcThreadAttribute(
			IntPtr lpAttributeList,
			uint dwFlags,
			IntPtr Attribute,
			IntPtr lpValue,
			IntPtr cbSize,
			IntPtr lpPreviousValue,
			IntPtr lpReturnSize);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool InitializeProcThreadAttributeList(
			IntPtr lpAttributeList,
			int dwAttributeCount,
			int dwFlags,
			ref IntPtr lpSize);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool CloseHandle(IntPtr hObject);
	}
"@

	$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
	
	# Needs Admin privs
	if (!$IsAdmin) 
	{
		Write-Output "`n[!] Administrator privileges are required!`n"
		Return
	}

	[System.Diagnostics.Process]::EnterDebugMode()
	
	$pi = New-Object PROCESS_INFORMATION
        $si = New-Object STARTUPINFOEX
        $si.StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
        $lpValue = [IntPtr]::Zero

	Try
	{
		$lpSize = [IntPtr]::Zero
		[Kernel32]::InitializeProcThreadAttributeList([IntPtr]::Zero, 1, 0, [ref]$lpSize) | Out-Null
		$si.lpAttributeList = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($lpSize)
		[Kernel32]::InitializeProcThreadAttributeList($si.lpAttributeList, 1, 0, [ref]$lpSize) | Out-Null
		$ProcHandle = (Get-Process -Id $ParentId).Handle
		Write-Output "`n[+] Process handle: $ProcHandle"
		$lpValue = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
		[System.Runtime.InteropServices.Marshal]::WriteIntPtr($lpValue, $ProcHandle)

		[Kernel32]::UpdateProcThreadAttribute($si.lpAttributeList, 
			0, 
			0x00020000,  # PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
			$lpValue, 
			[IntPtr]::Size, 
			[IntPtr]::Zero, 
			[IntPtr]::Zero) | Out-Null

		Write-Output "[+] Updated proc attribute list"
		
		$SecAttr = New-Object SECURITY_ATTRIBUTES
		$SecAttr.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($SecAttr)
		
		Write-Output "[+] Starting $Command ..."

		[Kernel32]::CreateProcess($Command, 
			$CommandArgs, 
			[ref]$SecAttr, 
			[ref]$SecAttr, 
			0,
			0x00080010, # EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE (This will show the window of the process)
			[IntPtr]::Zero, 
			"C:\Windows\System32", 
			[ref] $si, 
			[ref] $pi) | Out-Null

		$error = [Kernel32]::GetLastError()
		Write-Output "[*] $Command - pid: $($pi.dwProcessId) - Last error: $error`n"
	}
	finally
	{
		if ($si.lpAttributeList -ne [IntPtr]::Zero)
		{
			[Kernel32]::DeleteProcThreadAttributeList($si.lpAttributeList) | Out-Null
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($si.lpAttributeList)
		}
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpValue);
            
		if ($pi.hProcess -ne [IntPtr]::Zero)
		{
			[Kernel32]::CloseHandle($pi.hProcess)  | Out-Null
		}
		if ($pi.hThread -ne [IntPtr]::Zero)
		{
			[Kernel32]::CloseHandle($pi.hThread)  | Out-Null
		}
	}
}
