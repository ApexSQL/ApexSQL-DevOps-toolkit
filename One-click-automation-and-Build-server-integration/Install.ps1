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
	$modulesPath = "C:\Program Files\WindowsPowerShell\Modules\ApexSQL_DevOps_toolkit"
	$modulesPathRegex = "C:\\Program Files\\WindowsPowerShell\\Modules\\ApexSQL_DevOps_toolkit"
	$old_modulesPath = "C:\Program Files\ApexSQL\ApexSQL CICD toolkit\Modules"
	$old_modulesPathRegex = "C:\\Program Files\\ApexSQL\\ApexSQL CICD toolkit\\Modules"
    $old_CICDPath = "C:\Program Files\ApexSQL\ApexSQL CICD toolkit"
    $prev_modulesPath = "C:\Program Files\ApexSQL\ApexSQL DevOps toolkit\Modules"
	$prev_modulesPathRegex = "C:\\Program Files\\ApexSQL\\ApexSQL DevOps toolkit\\Modules"
    $old_DevOpsPath = "C:\Program Files\ApexSQL\ApexSQL DevOps toolkit"

    if (Test-Path $old_modulesPath)
	{
		Remove-Item $old_modulesPath -Recurse -Force | Out-Null
	}
    if (Test-Path $prev_modulesPath)
	{
		Remove-Item $prev_modulesPath -Recurse -Force | Out-Null
	}
    if (Test-Path $old_CICDPath)
	{
		Remove-Item $old_CICDPath -Recurse -Force | Out-Null
	}
    if (Test-Path $old_DevOpsPath)
	{
		Remove-Item $old_DevOpsPath -Recurse -Force | Out-Null
	}
	if (Test-Path $modulesPath)
    {
        Remove-Item $modulesPath -Recurse -Force | Out-Null
    }
    if (-not (Test-Path $modulesPath))
	{
		New-Item -Path $modulesPath -ItemType Directory -Force | Out-Null
	}
	if ((-not (Test-Path "$PSScriptRoot\ApexSQL_DevOps_toolkit.psd1")) -or (-not (Test-Path "$PSScriptRoot\ApexSQL_DevOps_toolkit.psm1")))
	{
		Write-Host "ApexSQL_DevOps_toolkit.psd1 or ApexSQL_DevOps_toolkit.psm1 files are not found in directory $PSScriptRoot.`r`n"
		Write-Host "Please download latest version of the installation files and run Install.ps1 again`r`n"
		pause
		exit
	}

	Copy-Item -Path "$PSScriptRoot\ApexSQL_DevOps_toolkit.psd1" -Destination $modulesPath -Force
	Copy-Item -Path "$PSScriptRoot\ApexSQL_DevOps_toolkit.psm1" -Destination $modulesPath -Force

	$currentValue = [Environment]::GetEnvironmentVariable("PSModulePath")
	if ($currentValue -match $old_modulesPathRegex)
    {
        [Environment]::SetEnvironmentVariable("PSModulePath", $currentValue.Replace("$old_modulesPath" ,""), "Machine")
    }
	if ($currentValue -match $prev_modulesPathRegex)
	{
		[Environment]::SetEnvironmentVariable("PSModulePath", $currentValue.Replace("$prev_modulesPath" ,""), "Machine")
	}
	Write-Host "Installation completed successfully"
}
catch
{
	Write-Host "Error during installation"
	Write-Host $_.Message
}
pause 
