$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

if (-not $myWindowsPrincipal.IsInRole($adminRole))
{
	Write-Host "Installation process requires Administrator privileges to run successfully.`r`nDo you want to start as Administrator?"
	$answer = "N"
	$answer = Read-Host "[Y] Yes [N] No (default is ""N"")"
	if("Y","Yes","y","yes" -match $answer)
	{
		$newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
		$newProcess.Arguments = $myInvocation.MyCommand.Definition;
		$newProcess.Verb = "runas";
		[System.Diagnostics.Process]::Start($newProcess);
	}
	exit
}
try
{
	$modulesPath = "C:\Program Files\ApexSQL\ApexSQL DevOps toolkit\Modules"
	$modulesPathRegex = "C:\\Program Files\\ApexSQL\\ApexSQL DevOps toolkit\\Modules"
	$old_modulesPath = "C:\Program Files\ApexSQL\ApexSQL CICD toolkit\Modules"
	$old_modulesPathRegex = "C:\\Program Files\\ApexSQL\\ApexSQL CICD toolkit\\Modules"
	$devopsPath = "C:\Program Files\ApexSQL\ApexSQL DevOps toolkit\Modules\ApexSQL_DevOps"
	if(-not (Test-Path $devopsPath))
	{
		New-Item -Path $devopsPath -ItemType Directory -Force | Out-Null
	}
	if ((-not (Test-Path "$PSScriptRoot\ApexSQL_DevOps.psd1")) -or (-not (Test-Path "$PSScriptRoot\ApexSQL_DevOps.psm1")))
	{
		Write-Host "ApexSQL_DevOps.psd1 or ApexSQL_DevOps.psm1 files are not found in directory $PSScriptRoot.`r`n"
		Write-Host "Please download latest version of the installation files and run Install.ps1 again`r`n"
		pause
		exit
	}
	Copy-Item -Path "$PSScriptRoot\ApexSQL_DevOps.psd1" -Destination $devopsPath -Force
	Copy-Item -Path "$PSScriptRoot\ApexSQL_DevOps.psm1" -Destination $devopsPath -Force
	Copy-Item -Path "$PSScriptRoot\Package.nuspec" -Destination $devopsPath -Force

	$currentValue = [Environment]::GetEnvironmentVariable("PSModulePath")
	if ($currentValue -notmatch $modulesPathRegex)
	{
		[Environment]::SetEnvironmentVariable("PSModulePath", $currentValue + ";$modulesPath", "Machine")
	}
	else
	{
		[Environment]::SetEnvironmentVariable("PSModulePath", $currentValue.Replace("$old_modulesPath" ,"$modulesPath"), "Machine")
		if (Test-Path "C:\Program Files\ApexSQL\ApexSQL CICD toolkit")
		{
			Remove-Item -Recurse -Force "C:\Program Files\ApexSQL\ApexSQL CICD toolkit"
		}
	}
	Write-Host "Installation completed successfully"
}
catch
{
	Write-Host "Error during installation"
	Write-Host $_.Message
}
pause
