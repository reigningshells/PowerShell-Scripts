function Import-ADModule
{
<#
.SYNOPSIS
This is a simple PowerShell script to import Microsoft.ActiveDirectory.Management.dll without writing DLL to disk.

.DESCRIPTION
This is a simple PowerShell script to import Microsoft.ActiveDirectory.Management.dll without writing DLL to disk.
The DLL byte array was compressed to cut down on the size of this file.

You can replace compressedADModule with a compressed byte array of your own Microsoft.ActiveDirectory.Management.dll 
if you don't trust mine :-P

.EXAMPLE
PS > Import-ActiveDirectory

Use the above command to import Microsoft.ActiveDirectory.Management.dll without writing it to disk.

.LINK
https://github.com/reigningshells

#>  

	[Byte[]] $compressedBytes = $compressedADModule -split ' '
	$input = New-Object System.IO.MemoryStream( , $compressedBytes )
	$output = New-Object System.IO.MemoryStream
	$gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	$gzipStream.CopyTo( $output )
	$gzipStream.Close()
	$input.Close()
	[byte[]] $ADModuleDLL = $output.ToArray()
	$Assembly = [System.Reflection.Assembly]::Load($ADModuleDLL)
	Import-Module -Assembly $Assembly
}