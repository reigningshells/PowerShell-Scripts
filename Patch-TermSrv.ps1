Function Patch-TermSrv
{
<#
.SYNOPSIS
This is a simple PowerShell PoC script to patch termsrv.dll in memory of the 
Remote Desktop Service to allow multiple concurrent sessions on Windows 10
Professional.

.DESCRIPTION
This is a simple PowerShell PoC script to patch termsrv.dll in memory of the 
Remote Desktop Service to allow multiple concurrent sessions on Windows 10
Professional.  It retrieves the PID of TermService, locates the base
address for termsrv.dll, then searches the memory from that point for
the pattern to be replaced by the patch.

Once patched, you can RDP to a box the same time another user is logged in.
Further in-memory patching can be leveraged to gain access to hardware
physically connected to the system not normally accessible to RDP users.

.EXAMPLE

PS > Patch-TermSrv

Use above command to patch Remote Desktop Services to allow multiple
concurrent sessions.

.LINK
https://github.com/reigningshells

#>

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	public static class Kernel32
	{

		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenProcess(
			UInt32 processAccess,
			bool bInheritHandle,
			UInt32 processId);

		[DllImport("kernel32.dll")]
		public static extern Boolean ReadProcessMemory( 
			IntPtr hProcess, 
			IntPtr lpBaseAddress,
			[Out] byte[] lpBuffer,
			UInt32 dwSize, 
			ref UInt32 lpNumberOfBytesRead);

		[DllImport("kernel32.dll")]
		public static extern bool WriteProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			byte[] lpBuffer,
			uint nSize,
			ref UInt32 lpNumberOfBytesWritten);

	}
"@

	Function arraysAreEqual($arr1,$arr2) 
	{
    		if ($arr1.Length -eq $arr2.Length) 
    		{
        		for($i = 0; $i -lt $arr1.Length; $i++)
        		{
           			if($arr1[$i] -ne $arr2[$i])
           			{
                			return $false
           		 	}
       			}
        		return $true
    		}
    		return $false
	}
  
	# Must be run from high integrity process
	if(($(whoami /groups) -like "*S-1-16-12288*").length -eq 0) {
		Write-Output "`n[!] Must be run as administrator!`n"
		Return
	}

	$ProcessId = (Get-WmiObject win32_service | where { $_.name -eq 'TermService'}).ProcessId
	$Process = Get-Process -Id $ProcessId
	$Dll = "termsrv.dll"
  
	$Module = $null
	foreach ($m in $Process.Modules)
	{
		if($m.ModuleName -eq $Dll)
		{
			$Module = $m
		}
	}

	if(!$Module)
	{
		Write-Output "Could not locate termsrv.dll mapped in memory."
		Return
	}

	$EndAddress = $Module.BaseAddress.ToInt64() + $Module.ModuleMemorySize - 12

	# PROCESS_ALL_ACCESS = 0x1F0FFF
	$hPID = [Kernel32]::OpenProcess(0x1F0FFF,$False,$ProcessId)

	if($hPID -eq [IntPtr]::Zero)
	{
		Write-Output "Failed to get handle on the process"
		Return
	}

	$Pattern = [Byte[]] @(0x39,0x81,0x3C,0x06,0x00,0x00,0x0F,0x84)
	$Patch = [Byte[]] @(0xB8,0x00,0x01,0x00,0x00,0x89,0x81,0x38,0x06,0x00,0x00,0x90)

	$Address = $Module.BaseAddress.ToInt64()
	$Found = $false
	while($Address -lt $EndAddress -and -not $Found)
	{
		$ReadSize = $Patch.Length
		$BytesRead = 0
		$Buffer = New-Object byte[] $ReadSize
		$null = [Kernel32]::ReadProcessMemory($hPID,[IntPtr]$Address,$Buffer,$ReadSize,[ref]$BytesRead)
		$Position = [array]::IndexOf($Buffer,$Pattern[0])
		switch($Position)
		{
			-1 { 
				$Address+=$ReadSize 
				Break
			}
			0 { 
				if(arraysAreEqual -arr1 $Buffer[0..($Pattern.Length - 1)] -arr2 $Pattern)
				{
					$Found = $true
				}
				else
				{
					$Address++
				}
				Break
			}
			default {
				$Address+=$Position
				Break
			}
		}
	}

	if($Found)
	{
		Write-Verbose "Found Pattern!"
		[UInt32]$BytesWritten = 0
		$CallResult = [Kernel32]::WriteProcessMemory($hPID,[IntPtr]$Address,$Patch,$Patch.Length,[ref]$BytesWritten)
		if($CallResult)
		{
			Write-Output "Successfully Patched!"
		}
	}
	else
	{
		Write-Output "Pattern Not Found!"
	}
}
