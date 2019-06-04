function Enable-Privilege 
{
<#
.SYNOPSIS
This is a simple PowerShell script to enable privileges on a process.

.DESCRIPTION
This is a simple PowerShell script to enable token privileges.

This function allows an elevated user to enable any disabled privileges on a process.

.PARAMETER ProcID
Process ID of the process who you with to enable a privilege for.

.PARAMETER Priv
Privilege you wish to enable.

.EXAMPLE

PS > Enable-Privilege -ProcID 1234 -Priv SeDebugPrivilege

Use above command to enable SeDebugPrivilege for process ID 1234.

.LINK
https://github.com/reigningshells

#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[int]$ProcID,

		[Parameter(Mandatory = $True)]
		[String]$Priv
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct TokPriv1Luid
	{
		public int Count;
		public long Luid;
		public int Attr;
	}
	
	public static class Advapi32
	{
		[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]		
		public static extern bool OpenProcessToken(		
			IntPtr ProcessHandle, 		
			uint DesiredAccess,		
			out IntPtr TokenHandle);
	
		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool GetTokenInformation(
			IntPtr TokenHandle,
			uint TokenInformationClass,
			IntPtr TokenInformation,
			int TokenInformationLength,
			ref int ReturnLength);
	
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool LookupPrivilegeValue(
			string lpSystemName,
			string lpName,
			ref long lpLuid);
			
		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool AdjustTokenPrivileges(
			IntPtr TokenHandle,
			bool DisableAllPrivileges,
			ref TokPriv1Luid NewState,
			int BufferLength,
			IntPtr PreviousState,
			IntPtr ReturnLength);
	}

	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern uint GetLastError();
	}

"@
		
	$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
	
	# Needs Admin privs
	if (!$IsAdmin) {
		Write-Output "`n[!] Administrator privileges are required!`n"
		Return
	}

	# Get process handle
	$ProcHandle = (Get-Process -Id $ProcID).Handle
	Write-Output "`n[+] Process handle: $ProcHandle"

	# Open token handle with TOKEN_ADJUST_PRIVILEGES bor TOKEN_QUERY
	Write-Output "`n[+] Calling Advapi32::OpenProcessToken"
	$hTokenHandle = [IntPtr]::Zero
	$CallResult = [Advapi32]::OpenProcessToken($ProcHandle, 0x28, [ref]$hTokenHandle)
	Write-Output "[+] Token handle with TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY: $hTokenHandle`n"

	# Prepare TokPriv1Luid container
	$TokPriv1Luid = New-Object TokPriv1Luid
	$TokPriv1Luid.Count = 1
	$TokPriv1Luid.Attr = 0x00000002 # SE_PRIVILEGE_ENABLED

	# Get privilege luid
	$LuidVal = $Null
	Write-Output "[+] Calling Advapi32::LookupPrivilegeValue --> $Priv"
	$CallResult = [Advapi32]::LookupPrivilegeValue($null, $Priv, [ref]$LuidVal)
	Write-Output "[+] $Priv LUID value: $LuidVal`n"
	$TokPriv1Luid.Luid = $LuidVal

	# Enable privilege for the process
	Write-Output "[+] Calling Advapi32::AdjustTokenPrivileges"
	$CallResult = [Advapi32]::AdjustTokenPrivileges($hTokenHandle, $False, [ref]$TokPriv1Luid, 0, [IntPtr]::Zero, [IntPtr]::Zero)
	if (!$CallResult) {
		$LastError = [Kernel32]::GetLastError()
		Write-Output "[!] GetLastError returned: $LastError`n"
		Return
	}
	Write-Output "[*] $Priv is enabled!`n"
}
