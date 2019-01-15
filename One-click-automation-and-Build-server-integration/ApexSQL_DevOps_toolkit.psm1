#region Classes
#[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", Scope="function", Target="*")]
#[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", Scope="function", Target="*")]
#[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSShouldProcess", Scope="function", Target="*")]
#[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", Scope="function", Target="*")]
#[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", Scope="function", Target="*")]
#[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingInvokeExpression", Scope="function", Target="*")]
#Param()

class ApexSqlConnection
{
    [string] $ConnectionName
}

class ApexSqlDatabaseConnection : ApexSqlConnection
{
	[string] $Server
    [string] $Database
    [bool]   $WindowsAuthentication
    [string] $UserName
    [string] $Password

    [string] AsParameters()
    {
        return $this.AsParameters("")
    }

    [string] AsParameters([string] $Variation)
    {
        if ($Variation -eq "doc")
        {
            $_username = ""
            $_password = ""
            if (-not $this.WindowsAuthentication)
            {
                $_username = ":$($this.UserName)"
                $_password = ".$($this.Password)"
            }
            return "/dbes:$($this.Server).$($this.Database)$_username$_password"
        }

        $id = ""
        if ($Variation -eq "diff1")
        {
            $id = "1"
        }
        if ($Variation -eq "diff2")
        {
            $id = "2"
        }
        $_server = "/server$($id):$($this.Server)"
        $_database = " /database$($id):$($this.Database)"
        $_username = ""
        $_password = ""
        if (-not $this.WindowsAuthentication)
        {
            $_username = " /user$($id):$($this.Username)"
            $_password = " /password$($id):$($this.Password)"
        }
	    return "$_server$_database$_username$_password"
    }
}

function New-ApexSqlDatabaseConnection
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
	    [string] $ConnectionName,

        [Parameter(Mandatory = $false)]
	    [string] $Server,

        [Parameter(Mandatory = $false)]
        [string] $Database,

        [Parameter(Mandatory = $false, ParameterSetName = "winAuth")]
        [switch] $WindowsAuthentication,

        [Parameter(Mandatory = $false, ParameterSetName = "credentials")]
        [string] $U,

        [Parameter(Mandatory = $false, ParameterSetName = "credentials")]
        [string] $P,

        [Parameter(Mandatory = $false, ParameterSetName = "credentials")]
        [string] $PasswordFile
    )
    $connection = New-Object -TypeName ApexSqlDatabaseConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Server   = $Server
    $connection.Database = $Database
    $connection.WindowsAuthentication = $WindowsAuthentication
    $connection.UserName = $U
    $connection.Password = (&{If(!$WindowsAuthentication -and !$U) {Get-Pass -PasswordFile $PasswordFile} Else {$U}})
    return $connection
}

class ApexSqlSourceControlConnection : ApexSqlConnection
{
    [string] $ConnectionName
    [string] $Source_Type
    [string] $UserName
    [string] $Password
    [string] $Project
    [string] $Server
    [string] $Repository
    [string] $Branch
    [string] $Label

    [string] AsParameters()
    {
        return $this.AsParameters("")
    }

    [string] AsParameters([string] $Variation = "")
    {
        $id = ""
        if ($Variation -eq "diff1")
        {
            $id = "1"
        }
        if ($Variation -eq "diff2")
        {
            $id = "2"
        }
        $_type = "/sourcecontrol_type$($id):$($this.Source_Type)"
        $_username = " /sourcecontrol_user$($id):$($this.UserName)"
        $_password = " /sourcecontrol_password$($id):$($this.Password)"
        $_project =  ""
        $_server = ""
        $_repository = ""
        $_branch = ""
        $_label = ""

        if ($this.Project)
        {
            $_project =  " /sourcecontrol_project$($id):""$($this.Project)"""
        }
        if ($this.Server)
        {
            $_server = " /sourcecontrol_server$($id):""$($this.Server)"""
        }
        if ($this.Repository)
        {
            $_repository = " /sourcecontrol_repository$($id):""$($this.Repository)"""
        }
        if ($this.Branch)
        {
            $_branch = " /sourcecontrol_branch$($id):""$($this.Branch)"""
        }
        if ($this.Label)
        {
            $_label = " /sourcecontrol_label$($id):""$($this.Label)"""
        }
        return "$_type$_username$_password$_project$_server$_repository$_branch$_label"
    }
}

function New-ApexSQLSource
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $ConnectionName,

        [Parameter(Mandatory = $false)]
        [ValidateSet("tfs","git","mercurial", "subversion", "perforce", "file", "nuget")]
        [String] $Source_Type,

        [Parameter(Mandatory = $false)]
        [string] $U,

        [Parameter(Mandatory = $false)]
        [string] $P,

        [Parameter(Mandatory = $false)]
        [string] $PasswordFile,

        [Parameter(Mandatory = $false)]
        [string] $Project,

        [Parameter(Mandatory = $false)]
        [string] $Server,

        [Parameter(Mandatory = $false)]
        [string] $Repository,

        [Parameter(Mandatory = $false)]
        [string] $Branch,

        [Parameter(Mandatory = $false)]
        [string] $Label,

        [Parameter(Mandatory = $false)]
        [string] $FilePath,

        [Parameter(Mandatory = $false)]
        [string] $FolderPath,

        [Parameter(Mandatory = $false)]
        [string] $NugetID,

        [Parameter(Mandatory = $false)]
        [string] $Version,

        [Parameter(Mandatory = $false)]
        [bool] $Latest,

        [Parameter(Mandatory = $false)]
        [string] $Source
     )

     if (!$P -and $Source_Type -ne "nuget")
     {
        $P = Get-Pass -PasswordFile $PasswordFile
     }
    if ($Source_Type -ne $null)
    {
        switch($Source_Type)
        {
            "tfs" { New-ApexSqlTfsSourceControlConnection -ConnectionName $ConnectionName -Server $Server -Project $Project -Label $Label -U $U -P $P }
            "git" { New-ApexSqlGitSourceControlConnection -ConnectionName $ConnectionName -Repository $Repository -Project $Project -Branch $Branch -Label $Label -U $U -P $P }
            "mercurial" { New-ApexSqlMercurialSourceControlConnection -ConnectionName $ConnectionName -Repository $Repository -Project $Project -Label $Label -U $U -P $P }
            "subversion" { New-ApexSqlSubversionSourceControlConnection -ConnectionName $ConnectionName -Repository $Repository -Project $Project -Label $Label -U $U -P $P  }
            "perforce" { New-ApexSqlPerforceSourceControlConnection -ConnectionName $ConnectionName -Server $Server -Repository $Repository -Project $Project -Label $Label -U $U -P $P }
            "file" { New-ApexSqlFileConnection -ConnectionName $ConnectionName -FilePath $Filepath }
            "sf" { New-ApexSqlSFConnection -ConnectionName $ConnectionName -FolderPath $Folderpath }
            "nuget" { New-ApexSqlNugetConnection -ConnectionName $ConnectionName -NugetID $NugetID -Version $Version -Source $Source }
            default { return }
        }
    }
    else
    {
        continue
    }

}

function New-ApexSqlGitSourceControlConnection
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
	    [string] $ConnectionName,

        [Parameter(Mandatory = $true)]
        [string] $Repository,

        [Parameter(Mandatory = $false)]
        [string] $Project,

        [Parameter(Mandatory = $false)]
        [string] $Branch,

        [Parameter(Mandatory = $false)]
        [string] $Label,

        [Parameter(Mandatory = $true)]
        [string] $U,

        [Parameter(Mandatory = $true)]
        [string] $P
    )

    $connection = New-Object ApexSqlSourceControlConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Source_Type = "git"
    $connection.Repository = $Repository
    $connection.Project = $Project
    $connection.Branch = $Branch
    $connection.Label = $Label
    $connection.UserName = $U
    $connection.Password = $P
    return $connection
}

function New-ApexSqlTfsSourceControlConnection
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
	    [string] $ConnectionName,

        [Parameter(Mandatory = $true)]
        [string] $Server,

        [Parameter(Mandatory = $false)]
        [string] $Project,

        [Parameter(Mandatory = $false)]
        [string] $Label,

        [Parameter(Mandatory = $true)]
        [string] $U,

        [Parameter(Mandatory = $true)]
        [string] $P
    )

    $connection = New-Object ApexSqlSourceControlConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Source_Type = "teamfoundationserver"
    $connection.Server = $Server
    $connection.Project = $Project
    $connection.Label = $Label
    $connection.UserName = $U
    $connection.Password = $P
    return $connection
}

function New-ApexSqlMercurialSourceControlConnection
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
	    [string] $ConnectionName,

        [Parameter(Mandatory = $true)]
        [string] $Repository,

        [Parameter(Mandatory = $false)]
        [string] $Project,

        [Parameter(Mandatory = $false)]
        [string] $Label,

        [Parameter(Mandatory = $true)]
        [string] $U,

        [Parameter(Mandatory = $true)]
        [string] $P
    )

    $connection = New-Object ApexSqlSourceControlConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Source_Type = "mercurial"
    $connection.Repository = $Repository
    $connection.Project = $Project
    $connection.Label = $Label
    $connection.UserName = $U
    $connection.Password = $P
    return $connection
}

function New-ApexSqlSubversionSourceControlConnection
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
	    [string] $ConnectionName,

        [Parameter(Mandatory = $true)]
        [string] $Repository,

        [Parameter(Mandatory = $false)]
        [string] $Project,

        [Parameter(Mandatory = $false)]
        [string] $Label,

        [Parameter(Mandatory = $true)]
        [string] $U,

        [Parameter(Mandatory = $true)]
        [string] $P
    )

    $connection = New-Object ApexSqlSourceControlConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Source_Type = "subversion"
    $connection.Repository = $Repository
    $connection.Project = $Project
    $connection.Label = $Label
    $connection.UserName = $U
    $connection.Password = $P
    return $connection
}

function New-ApexSqlPerforceSourceControlConnection
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
	    [string] $ConnectionName,

        [Parameter(Mandatory = $true)]
        [string] $Server,

        [Parameter(Mandatory = $true)]
        [string] $Repository,

        [Parameter(Mandatory = $false)]
        [string] $Project,

        [Parameter(Mandatory = $false)]
        [string] $Label,

        [Parameter(Mandatory = $true)]
        [string] $U,

        [Parameter(Mandatory = $true)]
        [string] $P
    )

    $connection = New-Object ApexSqlSourceControlConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Source_Type = "perforce"
    $connection.Server = $Server
    $connection.Repository = $Repository
    $connection.Project = $Project
    $connection.Label = $Label
    $connection.UserName = $U
    $connection.Password = $P
    return $connection
}

class ApexSqlFileConnection : ApexSqlConnection
{
    [string] $FilePath
}

function New-ApexSqlFileConnection
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
	    [string] $ConnectionName,

        [Parameter(Mandatory = $true)]
        [string] $FilePath
    )
    $connection = New-Object ApexSqlFileConnection
    $connection.ConnectionName = $ConnectionName
    $connection.FilePath = $FilePath
    return $connection
}

class ApexSqlSFConnection : ApexSqlConnection
{
    [string] $FolderPath
}

function New-ApexSqlSFConnection
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
	    [string] $ConnectionName,

        [Parameter(Mandatory = $true)]
        [string] $FolderPath
    )
    $connection = New-Object ApexSqlSFConnection
    $connection.ConnectionName = $ConnectionName
    $connection.FolderPath = $FolderPath
    return $connection
}

class ApexSqlNugetConnection : ApexSqlConnection
{
    [string] $NugetID
    [string] $Version
    [string] $Source
}

function New-ApexSqlNugetConnection
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
	    [string] $ConnectionName,

        [Parameter(Mandatory = $true)]
        [string] $NugetID,

        [Parameter(Mandatory = $false)]
        [string] $Version,

        [Parameter(Mandatory = $false)]
        [string] $Source
    )
    $connection = New-Object ApexSqlNugetConnection
    $connection.ConnectionName = $ConnectionName
    $connection.NugetID = $NugetID
    $connection.Version = $Version
    $connection.Source = $Source
    return $connection
}

class ApexSqlNotificationSettings
{
    [PSCredential] $Credential
    [string] $SmtpServer
    [bool]   $UseSSL
    [int]    $Port
}

function New-ApexSQLNotificationSettings
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ApexSqlOptions] $Options,

        [Parameter(Mandatory = $true)]
        [string] $EmailAddress,

        [Parameter(Mandatory = $false)]
        [string] $Password,

        [Parameter(Mandatory = $false)]
        [string] $PasswordFile,

        [Parameter(Mandatory = $true)]
        [string] $SmtpServer,

        [Parameter(Mandatory = $true)]
        [int]    $Port,

        [Parameter(Mandatory = $false)]
        [switch] $UseSSL
    )

    $Password = (&{If(!$Password) { (Get-Pass -PasswordFile $PasswordFile) } Else {$Password}})
    if ($null -ne $Password -and $Password -ne '')
    {
        $pass = New-Object System.Security.SecureString
        $Password.ToCharArray() | ForEach-Object { $pass.AppendChar($_) }
        $cred = New-Object System.Management.Automation.PSCredential ($EmailAddress, $pass)
    }
    else
    {
        $pass = ''
        $cred = New-Object System.Management.Automation.PSCredential ($EmailAddress)
    }

    $settings = New-Object -TypeName ApexSqlNotificationSettings
    $settings.Credential = $cred
    $settings.SmtpServer = $SmtpServer
    $settings.UseSSL     = $UseSSL
    $settings.Port       = $Port
    $Options.NotificationSettings = $settings
    return $settings
}

class ApexSqlOptions
{
    [string] $PipelineName = "MyPipeline"
    [string] $OutputLocation
    [string] $ScriptDirectory
	[ApexSqlNotificationSettings] $NotificationSettings
	[string] $OutputLogFile
    [string] $PackageFilePath
    [string] $Timestamp
	[string] $ErrorCodes
	[string] $FailedSteps
	[string] $Result = "Success"
}

function New-ApexSqlOptions
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $PipelineName,

        [Parameter(Mandatory = $false)]
        [string] $OutputLocation,

        [Parameter(Mandatory = $false)]
        [switch] $NoSubfolders
    )
    $timestamp = Get-Date -Format "MM-dd-yyyy_HH-mm-ss"
    $options = New-Object -TypeName ApexSqlOptions
    $options.PipelineName = $PipelineName
    $options.ScriptDirectory = $global:currentDirectory

    if (-not (Test-Path $global:nugetExePath))
    {
        throw "Incorrect nuget.exe file path defined in 'global:nugetExePath' variable."
    }

    if (!$OutputLocation )
    {
        $OutputLocation = $options.ScriptDirectory
    }

    if ($NoSubfolders)
    {
        $options.OutputLocation = $OutputLocation
    }
    else
    {
        $options.OutputLocation = "$OutputLocation\$PipelineName\$timestamp"
    }
    $options.Timestamp = $timestamp
	$options.OutputLogFile = "$($options.OutputLocation)\$($PipelineName)_job_summary.log"
    $options.NotificationSettings = $null

    if (-not (Test-Path $options.OutputLocation))
    {
        New-Item -Path $OutputLocation -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path $options.OutputLocation))
    {
        New-Item -Path $options.OutputLogFile -ItemType File -Force | Out-Null
    }
    $options.PackageFilePath = ""
    Initialize-Globals

    $pipelineStartedTimestamp = "$($timestamp.remove(2, 1).insert(2, "/").remove(5, 1).insert(5, "/").remove(10, 1).insert(10, " ").replace("-",":"))"
    $msg = "$($PipelineName) started at $($pipelineStartedTimestamp)"
    Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append
    return $options
}
#endregion

#region Helpers

function Initialize-Globals
{
    [CmdletBinding(SupportsShouldProcess)]
	param
    (
        [string] $CurrentDirectory
    )
    $global:currentDirectory = $CurrentDirectory
    $global:StaticDataSource_ForDataDiff = $null
    $global:StaticDataPath_ForDataDiff = $null
    $global:SkippingList = $null
    $global:nuspec = $null
    $global:nugetDatabaseScriptsSource = $null
    #Create and reset ResultSet
    $global:ResultSet = [ordered]@{}
    if ($null -eq $Options.Result)
    {
        $global:ResultSet.Clear()
    }
}

function GetSourceName
{
    [CmdletBinding()]
    [OutputType('System.String')]
	param
	(
        [Parameter(Mandatory = $true)]
        [string] $SourceName
    )
    switch($SourceName)
    {
        "Team Foundation Server" { return "teamfoundationserver" }
        "Git" { return "git" }
        "Mercurial" { return "mercurial" }
        "Subversion" { return "subversion" }
        "Perforce" { return "perforce" }
        "File" { return "file" }
    }
}

function GetStaticDataFolderPath
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true)]
        $Path
    )

        [xml]$projecFile = Get-Content $Path
        $SourceControllInfo = $projecFile.ApexSQLBuildProject.ProjectOptions.Options.Option | Where-Object { $_.id -eq "SourceControlConnection"}
        $SourceFolder = $SourceControllInfo.ScConnectionInfo.SourceControlFolder
        return $SourceFolder + "\Tables\StaticData"
}

function GetToolName
{
    param
    (
        [string] $Step
    )
    switch ($Step)
    {
        "Build" {return "ApexSQL Build"}
        "Populate" {return "ApexSQL Generate"}
        "Audit" {return "ApexSQL Trigger"}
        "Review" {return "ApexSQL Enforce"}
        "Test" {return "ApexSQL Unit Test"}
        "Script" {return "ApexSQL Script"}
        "Document" {return "ApexSQL Doc"}
        "Sync" {return "ApexSQL Diff"}
        "Sync data" {return "ApexSQL Data Diff"}
        "Package" {return "ApexSQL Package"}
        "Deploy" {return "ApexSQL Deploy"}
        default {return}
    }
}

function GetStepName
{
    param
    (
        [string] $Tool
    )
    switch ($Tool)
    {
        "Build" {return "Build"}
        "Generate" {return "Populate"}
        "Trigger" {return "Audit"}
        "Enforce" {return "Review"}
        "Unit Test" {return "Test"}
        "Script" {return "Script"}
        "Doc" {return "Document"}
        "Diff" {return "Sync"}
        "Data Diff" {return "Sync data"}
        "Package" {return "Package"}
        "Deploy" {return "Deploy"}
        default {return}
    }
}

function Get-Pass
{
    param
    (
        [string] $PasswordFile
    )
    if ($PasswordFile.Length -gt 0)
    {
        $filePath = "$($options.ScriptDirectory)\Passwords\$($PasswordFile).txt"
        if (Test-Path -Path $filePath -PathType leaf)
        {
            $EncryptedPass = (Get-Content -Path $filePath)
            if ($EncryptedPass.Length -gt 0)
            {
                $DecryptedPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString $EncryptedPass) ))
            }
            else
            {
                $msg = "No password provided in file ""$($filePath)!"""
                Write-Warning $msg
                Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append
                exit(1)
            }
        }
        else
        {
            $msg = "The file ""$($filePath)"" doesn't exist!"
            Write-Warning $msg
            Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append
            exit(1)
        }
    }
    else
    {
        $msg = "No password file is provided!"
        Write-Warning $msg
        Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append
        exit(1)
    }


    return $DecryptedPass
}

function Get-ApexSQLToolLocation
{
    param
    (
        [Parameter(Mandatory = $true)]
        [String] $ApplicationName
    )
    $key = Get-ChildItem HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ -Recurse |Where-Object {$_.PSChildName -like "ApexSQL $($ApplicationName)*_is1"}
    $key = $key.Name
    if (Test-Path "HKLM:\$Key")
    {
		$ApplicationPath = (Get-ItemProperty -Path "HKLM:\$key" -Name InstallLocation).InstallLocation
	}
    else
    {
		$reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)

		$regKey= $reg.OpenSubKey("$key")
		if ($regKey)
        {
			$ApplicationPath = $regKey.GetValue("InstallLocation")
		}
        else
        {
			$reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)
			$regKey= $reg.OpenSubKey("$key")
			if ($regKey)
            {
				$ApplicationPath = $regKey.GetValue("InstallLocation")
			}
            else
            {
				Out-File -FilePath $Options.OutputLogFile -InputObject "ApexSQL $ApplicationName is not installed" -Append
                $Options.ErrorCodes += @("Not installed")
                $Options.FailedSteps += @("ApexSQL $ApplicationName")
                $Options.Result = "Failure"
                return $null
			}
		}
	}
    if ($ApplicationPath)
    {
        return $ApplicationPath + "ApexSQL" + $ApplicationName.replace(' ','') + ".com"
    }
}

function Start-ApexSQLTool
{
    [CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory = $true)]
		[string] $ToolName,
		[Parameter(Mandatory = $true)]
		[string] $ToolParameters,
		[Parameter(Mandatory = $true)]
		[ApexSqlOptions] $Options,
		[Parameter(Mandatory = $true)]
		[bool] $StopOnFail,
        [Parameter(Mandatory = $false)]
		[bool] $FromPackage,
        [Parameter(Mandatory = $false)]
		[bool] $Silent,
        [Parameter(Mandatory = $false)]
		[string] $OutputFiles
	)


	$logFile = "$OutputLocation\$($PipelineName).log"
    $thisIsPackageStep = $false

	$toolLocation = Get-ApexSQLToolLocation $ToolName
    if (-not $toolLocation)
    {
        return $false
    }

    $info = ""
    if ($ToolName -ne "Script")
    {
        if ($Silent -ne $true)
        {
            if ($FromPackage -eq $true -and $ToolName -eq "Data Diff")
                        {
                        $thisIsPackageStep = $true
	        $info = "`r`n`r`n`t`t----- Started collecting static data -----`r`n" +
                        "`t`t------------------------------------------`r`n"
        }
            else
            {
            $info = "`r`n`r`n============================" + ("=" * $ToolName.Length) + "==============`r`n" +
                            "----- Starting execution of ApexSQL $ToolName -----`r`n" +
                            "------------------------------" + ("-" * $ToolName.Length) + "------------`r`n"
        }
        }
    }
    else
    {
        $info = "`r`n`r`n`t----- Started scripting the database -----`r`n" +
                        "`t------------------------------------------`r`n"
    }
	Out-File -FilePath $Options.OutputLogFile -InputObject $info -Append
	$output = Invoke-Expression -Command ("& `"$($toolLocation)`" $ToolParameters")
	Out-File -FilePath $Options.OutputLogFile -InputObject $output -Append

	if ($lastExitCode -ne 0 -and -not ($lastExitCode -eq 104 -and $ToolName -eq "Generate"))
	{
		$Options.FailedSteps += @("ApexSQL $ToolName")
        $Options.ErrorCodes += @($lastExitCode)
		if ($StopOnFail)
		{
			$errorText = "`r`nApexSQL $ToolName failed.`r`nThe process is canceled due to failure return code: $lastExitCode"
			Out-File -FilePath $Options.OutputLogFile -InputObject $errorText -Append
			$Options.Result = "Failure"
            $stepName = GetStepName -Tool $ToolName
            $msg = "$stepName step failed."
            Write-Warning $msg
            $global:ResultSet.Add($global:ResultSet.Count, @{Step=$stepName; Result='Failure'; ErrorCode=$lastExitCode;})
            return $false
		}
		else
		{
			$Options.Result = "Completed with errors"
		}
	}
    else
    {
        if ($thisIsPackageStep)
        {
            $global:ResultSet.Add($global:ResultSet.Count, @{Step="Package"; Result='Success'; OutputFiles=(&{ if ($null -ne $OutputFiles) {"$($OutputFiles)"} Else {""}} )})
        }
        if ($ToolName -ne "Script" -and $Silent -ne $true -and ($FromPackage -eq $true -and $ToolName -eq "Data Diff") -ne $true)
        {

            $stepName = GetStepName -Tool $ToolName
            $msg = "$stepName step passed."
            Write-Verbose $msg
            Out-File -FilePath $Options.OutputLogFile -InputObject "`r`n##### $($msg) #####`r`n" -Append
            $global:ResultSet.Add($global:ResultSet.Count, @{Step=$stepName; Result='Success'; OutputFiles=(&{ if ($null -ne $OutputFiles) {"$($OutputFiles)"} Else {""}} )})
        }
    }
    return $true
}

function DisplayCommandLineArgs()
{
    $msg =
    "`t`t- NuGet ID: $nugetId`r`n" +
    "`t`t- Version: $nugetVersion`r`n" +
    "`t`t- Source: $($Options.OutputLocation)`r`n" +
    "`t`t- Destination: $($Options.OutputLocation)"
    Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append

    # Setup the nuget path.
    if (-Not $nuget -eq "")
    {
        $global:nugetExe = $nuget
    }
    else
    {
        # Assumption, nuget.exe is the current folder Where-Object this file is.
        $global:nugetExe = Join-Path $source "nuget"
    }

    $global:nugetExe

    if (!(Test-Path $global:nugetExe -PathType leaf))
    {
        $errorText = "'nuget.exe' file was not found. Please provide correct 'nuget.exe' file path.`r`nProces terminated."
        Write-Warning -Message $errorText
        Out-File -FilePath $Options.OutputLogFile -InputObject "`r`n`t$($errorText)" -Append
        $Options.ErrorCodes += @($LastExitCode)
        $Options.FailedSteps += @("ApexSQL Package")
        $Options.Result = "Failure"
        return
    }
}

function CleanUp()
{
    if ($clean -eq $false)
    {
        return;
    }

    $nupkgFiles = @(Get-ChildItem $destination -Filter *.nupkg)

    if ($nupkgFiles.Count -gt 0)
    {
        "Found " + $nupkgFiles.Count + " *.nupkg files. Lets delete these first..."

        foreach($nupkgFile in $nupkgFiles)
        {
            $combined = Join-Path $destination $nupkgFile
            "... Removing $combined."
            Remove-Item $combined
        }

        "... Done!"
    }
}

function PackageTheSpecification()
{
    # Create template .nuspec file
    $nuspecContent = 
@'
<?xml version="1.0"?>
<package >
  <metadata>
    <id>$id$</id>
    <version>$version$</version>
    <authors>$authors$</authors>
    <owners>$owners$</owners>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <description>$description$</description>
    <releaseNotes>$releaseNotes$</releaseNotes>
    <copyright>Copyright 2017 - ApexSQL LLC</copyright>
    <tags></tags>
  </metadata>
</package>
'@

    New-Item -Path $Options.OutputLocation -Name "Package.nuspec" -ItemType "file" -Value $nuspecContent

    $shema = $null
    $data = $null
    $consolidatedScript = "$($Options.OutputLocation)\Consolidated_script.sql"
    if ($Consolidate)
    {
        $shema = Get-ChildItem -Path $Options.OutputLocation -Filter SchemaSync_*.sql
        $data =Get-ChildItem -Path $Options.OutputLocation -Filter DataSync_*.sql

        if ($null -ne $shema)
        {
            $content += Get-Content -Path "$($Options.OutputLocation)\$shema"
            Remove-Item "$($Options.OutputLocation)\$shema"
        }
        if ($null -ne $data)
        {
            $content += Get-Content -Path "$($Options.OutputLocation)\$data"
            Remove-Item "$($Options.OutputLocation)\$data"
        }
        if ($content)
        {
            $content > $consolidatedScript
        }
        $content = $null
    }


    #Create list of all files included in .nupkg
    #(this is all files from all included steps excluding Project.nuspec which serves as a template and being removed)
    $files = "`r`nContent of this package version:`r`n"
    $content = Get-ChildItem $Options.OutputLocation -Exclude *.nuspec, *_job_summary.log
    foreach($file in $content)
    {
        $files += "$($file.Name)`r`n"
        $fileNames += "`r`n`t`t- $($file.Name)"
    }

    if ($null -ne $content)
    {
        $msg = "`tStarted creating the package ...`r`n"
        Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append

        DisplayCommandLineArgs
        if ($Options.Result -eq "Failure")
        {
            if ($PSCmdlet.MyInvocation.ExpectingInput)
            {
                return $Options
            }
            else
            {
                return
            }
        }

        $logContent = $null
        try
        {
            #Remove log file (and store its content to temp variable in order to get back the content to log file)
            $logContent = Get-Content $Options.OutputLogFile -Raw
            Remove-Item $Options.OutputLogFile

            #Execute packing
            &$nugetExe pack "$($Options.OutputLocation)" -Properties id=$nugetId -Properties version=$nugetVersion -Properties authors=$nugetAuthors -Properties owners=$nugetOwners -Properties description=$files -Properties releaseNotes=$nugetReleaseNotes -OutputDirectory "$($Options.OutputLocation)"

            #Get back log content to log file
            $logContent > $Options.OutputLogFile
            $logContent = $null

            $msg = "`tPackage successfully created."
            Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append
            $msg = "`r`n`tContent of this package version:" + $fileNames
            Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append
        }
        catch
        {
            #Get back log content to log file
            $logContent > $Options.OutputLogFile
            $logContent = $null

            $errorText = "Creating the package failed.`r`n"
            Write-Warning -Message $errorText
            Out-File -FilePath $Options.OutputLogFile -InputObject "`t$($errorText)" -Append

            if ($null -eq $LASTERRORCODE -and $LASTERRORCODE -lt 0)
            {
                $lastReturnCode = 1
            }
            $Options.ErrorCodes += $lastReturnCode
            $Options.FailedSteps += @("ApexSQL Package")
            $Options.Result = "Failure"
            return
        }
    }

    else
    {
        $errorText = "Creating the package failed. Package can not be empty.`r`n"
        Write-Warning -Message $errorText
        Out-File -FilePath $Options.OutputLogFile -InputObject "`t$($errorText)" -Append
        $lastReturnCode = $LASTERRORCODE
        if ($null -eq $LASTERRORCODE -and $LASTERRORCODE -lt 0)
        {
            $lastReturnCode = 1
        }
        $Options.ErrorCodes += $lastReturnCode
        $Options.FailedSteps += @("ApexSQL Package")
        $Options.Result = "Failure"
        return
    }


    #Remove templete .nuspec file
    Remove-Item "$($Options.OutputLocation)\Package.nuspec"

    #Get .nupkg file name to add it to $outputs
    $packageName = @(Get-ChildItem "$($Options.OutputLocation)" -Filter *.nupkg)
    $global:ResultSet[$global:ResultSet.Count - 1]["OutputFiles"]=$packageName.Name
    $packageName = $packageName.FullName
    $Options.PackageFilePath = $packageName

    #If DoNotRemoveContents switch missing remove all files (except .nupkg and .log)
    if (!$DoNotRemoveContents)
    {
        Get-Childitem "$($Options.OutputLocation)" -Exclude *.nupkg, *_job_summary.log | ForEach-Object ($_) {remove-item $_.fullname -Recurse -Force}
    }
}

function PublishPackage()
{
    [CmdletBinding()]
	param
    (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string] $Destination,

    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string] $ApiKey
    )

    if ($ApiKey -eq "")
    {
        $errorText = "No NuGet server api key provided - so not pushing anything up."
        Write-Warning -Message $errorText
        Out-File -FilePath $Options.OutputLogFile -InputObject $errorText -Append
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

    $msg = "`r`n`t----------`r`n`r`n`tStarted publishing the package ...`r`n"
    Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append

    $msg = "`t`tGetting all *.nupkg's files to push to: $pushSource"
    Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append

    $files = Get-ChildItem $Destination -Filter *.nupkg

    if ($files.Count -eq 0)
    {
        $errorText = "No nupkg files found in the directory: $destination`r`n`tTerminating process."
        Write-Warning -Message $errorText
        Out-File -FilePath $Options.OutputLogFile -InputObject "`t`t$($errorText)" -Append
        $Options.ErrorCodes += 1
        $Options.FailedSteps += @("ApexSQL Package")
        $Options.Result = "Failure"
        return
    }

    foreach($file in $files)
    {
        $fileNames += "`r`n`t`t`t- $($file.Name)"
    }

    $msg = "`t`tFound:" + $fileNames
    Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append

    foreach($file in $files)
    {
        try
        {
            &$nugetExe push ($file.FullName) -Source $pushSource -apiKey $ApiKey

            $msg = "`r`n`tPackage successfully published."
            Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append

        }
        catch
        {
            $errorText = "`tPackage publishing failed: `r`n`t`t>>$($_.Exception.Message)<<"
            Write-Warning -Message $errorText
            Out-File -FilePath $Options.OutputLogFile -InputObject $errorText -Append
            $lastReturnCode = $LastExitCode
            if ($LastExitCode -ne 0 -and $LastExitCode -lt 0)
            {
                $lastReturnCode = 1
            }
            $Options.ErrorCodes += $lastReturnCode
            $Options.FailedSteps += @("ApexSQL Package")
            $Options.Result = "Failure"
        }
    }


}

function ExtractNupkg ()
{
    param
    (
        [string] $OutputLocation,
        [string] $NugetID,
        [string] $Version,
        [string] $Source,
        [string] $nuget = $global:nugetExePath
    )

    $msg = "`r`n`t----------`r`n`r`n`tStarted Extracting the package ...`r`n"
    Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append

    if (!$Source -or $null -eq $Source -or $Source -eq "")
    {
        $Source = "$($OutputLocation)\\"
    }

    if (-Not $Version)
    {
        try
        {
            &$nuget install $NugetID -Output $OutputLocation -Source "$($Source)" >> $Options.OutputLogFile
            $msg = "`r`n`tPackage successfully extracted.`r`n`r`n`t----------`r`n"
            Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append
        }
        catch
        {
            $errorText = "`tThere was some problem in extracting the .nupkg file.`r`n`t`t>>$($_.Exception.Message)<<"
            Write-Warning -Message $errorText
            Out-File -FilePath $Options.OutputLogFile -InputObject $errorText -Append
            $Options.ErrorCodes += 1
            $Options.FailedSteps += @("Extracking the package")
            $Options.Result = "Failure"
        }
    }
    else
    {
        try
        {
            &$nuget install $NugetID -Version $Version -Output $OutputLocation -Source $Source >> $Options.OutputLogFile
            $msg = "`tPackage successful extracted.`r`n`r`n`t----------`r`n"
            Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append
        }
        catch
        {
            $errorText = "`tThere was some problem in extracting the .nupkg file.`r`n`t`t>>$($_.Exception.Message)<<"
            Write-Warning -Message $errorText
            Out-File -FilePath $Options.OutputLogFile -InputObject $errorText -Append
            if ($PSCmdlet.MyInvocation.ExpectingInput)
            {
                return $Options
            }
            else
            {
                return
            }
        }
    }
}

function ClearExtractedContents ()
{
    param
    (
        [string] $path
    )

    Get-Childitem $path | Where-Object {$_.Name -notlike "*DatabaseScripts*"} | ForEach-Object ($_) {remove-item $_.fullname -Recurse }
}

function RemoveSnapshots ()
{
    param
    (
        [string] $Location
    )

    $Db_SnapShot = "$($Location)\Db_SnapShot.axsnp"
    $Db_SnapShot_Diff = "$($Location)\Db_SnapShot_Diff.axdsn"

    #Remove snapshots
    if (Test-Path $Db_SnapShot)
    {
      Remove-Item $Db_SnapShot
    }
    if (Test-Path $Db_SnapShot_Diff)
    {
      Remove-Item $Db_SnapShot_Diff
    }
}

function Set-ProjectSwitch
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,
        [string] $ProjectFile,
        [ApexSqlConnection] $BuildStepSource,
        [Switch] $ReviewStep
    )
    $project = ""
	if ($ProjectFile)
	{
        $ProjectFile = $Options.ScriptDirectory + "\Projects\" + $ProjectFile
        if (-not $ReviewStep)
        {
            $project = "/project:""$ProjectFile"""
        }
        else
        {
            $project = "/rb:""$ProjectFile"""
        }
        
        if ($null -eq $BuildStepSource)
        {
            $global:StaticDataPath_ForDataDiff = GetStaticDataFolderPath -Path "$($ProjectFile)"
        }
    }
    return $project
}

function Set-AdditionalSwitch
{
    [CmdletBinding()]
    param
    (
        [string] $Additional
    )
    $additional = ""
	if ($Additional)
	{
        $additional = $Additional
    }
    return $additional
}

function LogFail
{
    [CmdletBinding()]
    param
    (
        [string] $ErrorText,
        [string] $FilePath
    )
    Write-Warning -Message $errorText
    Out-File -FilePath $FilePath -InputObject $ErrorText -Append
}

#endregion




function Invoke-ApexSqlBuildStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

		[Parameter(Mandatory = $false)]
        [ValidateScript({
            if (($_.GetType() -ne [ApexSqlSourceControlConnection]) -and ($_.GetType() -ne [ApexSqlFileConnection]))
            {
                Throw "Only source control or file connection can be used as a source"
            }
            return $true
        })]
		[ApexSqlConnection] $Source,

        [ValidateScript({
            if (($_.GetType() -ne [ApexSqlDatabaseConnection]))
            {
                Throw "Only database can be used as a destination"
            }
            return $true
        })]
        [Parameter(Mandatory = $false)]
        [ApexSqlConnection] $Database,

		[Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true,

		[Parameter(Mandatory = $false)]
		[string] $ProjectFile,

		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions,

        [Parameter(Mandatory = $false)]
		[switch] $ExcludeStaticData,

        [Parameter(Mandatory = $false)]
        [switch] $NoScript,

        [Parameter(Mandatory = $false)]
        [string] $scPass,

        [Parameter(Mandatory = $false)]
        [string] $dbPass
	)
    if ($Options.Result -eq "Failure")
    {
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Skipping ApexSQL Build step due to failure in the pipeline"
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

    if (($null -eq $Source -and $null -eq $Database) -and $null -eq $ProjectFile)
    {
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Source and Database or a Project file must be set"
        return $Options
    }

    $project = Set-ProjectSwitch -Options $Options -ProjectFile $ProjectFile -BuildStepSource $Source
    $additional = Set-AdditionalSwitch -Additional $AdditionalOptions

    #Step-related params
    $static_data = " /isd "
    if ($ExcludeStaticData)
    {
        $static_data = ""
    }

    #Configure Source parameters
    $sourceType = "sc"
    if ($null -ne $Source)
    {
        if ($Source.GetType() -eq [ApexSqlFileConnection])
        {
            $sourceType = "sql"
            $sourceParams = "/source_name:""$($Source.FilePath)"""
        }
	    else
	    {
		    $sourceParams = $Source.AsParameters()
	    }

        #Storing Source for DataDiff in Script step - Static Data copying (add '1' to all source parameters [/s: => /s1: ...])
        $global:StaticDataSource_ForDataDiff = $($sourceParams).replace(":", "1:").replace("http1:","http:").replace("https1:","https:")
    }

    #Configure Database parameters
    $databaseType = "db"
    if ($null -ne $Database)
    {
	    $databaseParams = $Database.AsParameters()
    }



    #Full tool parameters
    $toolParameters =
    @{$true = "/source_type:$sourceType $sourceParams /output_type:$databaseType $databaseParams "; $false = " $project "}[!$ProjectFile] +
	    " $additional $static_data  /drop_if_exists /script_permissions /v /f"
	$params = @{
		ToolName = "Build"
		ToolParameters = $toolParameters
		Options = $Options
		StopOnFail = $StopOnFail
	}

    #Execute the tool
	Start-ApexSQLTool @params
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }

    #$global:ResultSet.Add($global:ResultSet.Count, @("Build", (&{ if ($null -ne $Options.Result) {"$($Options.Result)"} Else {""}} ), $null, (&{ if ($null -ne $Options.ErrorCodes) {"$($Options.ErrorCodes)"} Else {""}} )))
}

function Invoke-ApexSqlPopulateStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

		[Parameter(Mandatory = $false)]
		[ApexSqlDatabaseConnection] $Database,

        [Parameter(Mandatory = $false)]
        [int] $RowCount,

        [Parameter(Mandatory = $false)]
        [switch] $FillAllTables,

        [Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true,

		[Parameter(Mandatory = $false)]
		[string] $ProjectFile,

		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions,

        [Parameter(Mandatory = $false)]
        [switch] $NoScript
	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tPopulate`r`n"
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Skipping ApexSQL Populate step due to failure in the pipeline"
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

	$project = Set-ProjectSwitch -Options $Options -ProjectFile $ProjectFile
    $additional = Set-AdditionalSwitch -Additional $AdditionalOptions

    $fillEmpty = ""
    if (!$FillAllTables)
    {
       $fillEmpty = " /foet"
    }

    #Output files names
    $scriptName = "$($Options.OutputLocation)\Populate_$($Database.ConnectionName)_PopulateScript.sql"

    $db = (&{ if ($Database) {"$($Database.AsParameters()) "} Else {""}} )
    $rows = (&{ if ($RowCount) {"/r:$RowCount "} Else {""}} )

	$toolParameters = "$($db) $($rows) $fillEmpty $project $additional /v /f "
	$params = @{
		ToolName = "Generate"
		ToolParameters = $toolParameters
		Options = $Options
		StopOnFail = $StopOnFail
	}

    #Execute the tool
	Start-ApexSQLTool @params | Out-Null

    if ($LASTEXITCODE -eq 104)
    {
        $msg = "There are no empty tables in database: $($Database.Database)"
        Write-Warning -Message $msg
    }

    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
}

function Invoke-ApexSqlAuditStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

		[Parameter(Mandatory = $false)]
		[ApexSqlDatabaseConnection] $Database,

		[Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true,

		[Parameter(Mandatory = $false)]
		[string] $ProjectFile,

		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions,

        [Parameter(Mandatory = $false)]
		[switch] $NoScript,

        [Parameter(Mandatory = $false)]
		[switch] $NoReport,

        [Parameter(Mandatory = $false)]
		[switch] $OverwriteExistingTriggers,

        [Parameter(Mandatory = $false)]
		[string] $ExcludeTables

	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tAudit`r`n"
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Skipping ApexSQL Audit step due to failure in the pipeline"
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

    $project = Set-ProjectSwitch -Options $Options -ProjectFile $ProjectFile
    $additional = Set-AdditionalSwitch -Additional $AdditionalOptions

    $db = (&{ if ($Database) {"$($Database.AsParameters())"} Else {""}} )


    #Output files names
    $reportName = "$($Options.OutputLocation)\AuditReport.pdf"

    #Full tool parameters
    $outReport = ""
    if (!$NoReport)
    {
        $outReport = "/sr /rf:pdf /or:""$($reportName)"""
    }
    $eat = " /eat "
    if ($OverwriteExistingTriggers)
    {
        $eat = ""
    }
    $et = ""
    if ($ExcludeTables)
    {
        $et = " /et:$($ExcludeTables) "
    }
    $toolParameters = "$($db) $project $additional /at $($eat) $($et) $outReport /v /f"
    $params = @{
        ToolName = "Trigger"
        ToolParameters = $toolParameters
        Options = $Options
        StopOnFail = $StopOnFail
        OutputFiles = if ($NoReport) {""} else {"AuditReport.pdf"}
    }

    #Execute the tool
    Start-ApexSQLTool @params
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
}

function Invoke-ApexSqlReviewStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

		[Parameter(Mandatory = $true)]
		[ApexSqlDatabaseConnection] $Database,

        [Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true,

		[Parameter(Mandatory = $true)]
		[string] $ProjectFile,

		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions,

        [Parameter(Mandatory = $false)]
        [switch] $NoReport,

        [Parameter(Mandatory = $false)]
        [switch] $Passed,

        [Parameter(Mandatory = $false)]
        [switch] $Failed,

        [Parameter(Mandatory = $false)]
        [switch] $Errors
   	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tReview`r`n"
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Skipping ApexSQL Review step due to failure in the pipeline"
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

    $project = Set-ProjectSwitch -Options $Options -ProjectFile $ProjectFile -ReviewStep
    $additional = Set-AdditionalSwitch -Additional $AdditionalOptions

    #Output files names
    $reportName = "$($Options.OutputLocation)\ReviewReport.html"
    $scriptName = "$($Options.OutputLocation)\Review_$($Database.ConnectionName)_FixScript.sql"

    #Report contents
    $reportContents
        if ($Passed)
        {
            $reportContents += " /os:p"
        }
        if ($Failed)
        {
            $reportContents += " /os:f"
        }
        if ($Errors)
        {
            $reportContents += " /os:e"
        }

    #Full tool parameters
    $outReport = ""
    if (!$NoReport)
    {
        $outReport = "/ot:h /on:""$($reportName)"""
    }
	$toolParameters = " $($Database.AsParameters()) $project $($additional) $($outReport) $($reportContents) /v /f"
	$params = @{
		ToolName = "Enforce"
		ToolParameters = $toolParameters
		Options = $Options
		StopOnFail = $StopOnFail
        OutputFiles = "ReviewReport.html"
	}

    #Execute the tool
    Start-ApexSQLTool @params
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
}

function Invoke-ApexSqlTestStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

		[Parameter(Mandatory = $true)]
		[ApexSqlDatabaseConnection] $Database,

        [Parameter(Mandatory = $false)]
		[string] $ProjectFile,

		[Parameter(Mandatory = $false)]
		[switch] $InstallSqlCop,

		[Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true,

		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions,

        [Parameter(Mandatory = $false)]
        [switch] $NoReport
	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tTest`r`n"
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Skipping ApexSQL Test step due to failure in the pipeline"
        return $Options
    }

    $project = Set-ProjectSwitch -Options $Options -ProjectFile $ProjectFile
    $additional = Set-AdditionalSwitch -Additional $AdditionalOptions

    #sqlCop to install
	$sqlCop = ""
	if ($InstallSqlCop)
	{
		$sqlCop = " /install_sqlcop"
	}

    #Output files names
    $testReport = "$($Options.OutputLocation)\TestReport.xml"

    #Full tool parameters
    $outReport = ""
    if (!$NoReport)
	{
        $outReport = "/or:""$($testReport)"""
    }
    $toolParameters = "$($Database.AsParameters()) $outReport $sqlCop $project $additional /install_tsqlt /v /f"
	$params = @{
		ToolName = "Unit Test"
		ToolParameters = $toolParameters
		Options = $Options
		StopOnFail = $StopOnFail
        OutputFiles = "TestReport.xml"
	}

    #Execute the tool
    Start-ApexSQLTool @params
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
}

function Invoke-ApexSqlScriptStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

		[Parameter(Mandatory = $false)]
		[ApexSqlDatabaseConnection] $Database,

        [Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true
	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tScript`r`n"
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Skipping ApexSQL Script step due to failure in the pipeline"
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

    $scriptFolder = "$($Options.OutputLocation)\DatabaseScripts\"
    New-Item -ItemType Directory -Path "$($scriptFolder)" -F

    #region Script
    #Full tool parameters
	$toolParameters = " $($Database.AsParameters()) /fl:""$($scriptFolder)"" /exc:16384:SQLCop:tSQLt /exc:134217728:tSQLtCLR /eso /in /v /f"
	$params = @{
		ToolName = "Script"
		ToolParameters = $toolParameters
		Options = $Options
		StopOnFail = $StopOnFail
	}

    #Execute the tool (ApexSQL Script)
	Start-ApexSQLTool @params
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
    #endregion

    #region DataDiff

    #Full tool parameters

    if ($null -ne $global:StaticDataSource_ForDataDiff)
    {
        $toolParametersDataDiff = " $global:StaticDataSource_ForDataDiff /sf2:""$($scriptFolder)"" /o:8 /sync /f"
        $paramsDD = @{
		    ToolName = "Data Diff"
            ToolParameters = $toolParametersDataDiff
            Options = $Options
		    StopOnFail = $StopOnFail
            FromPackage = $true
	    }

        #Execute the tool (ApexSQL Data Diff)
        Start-ApexSQLTool @paramsDD
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }

    }
    else
    {
        $tempSrcPath = "$($global:StaticDataPath_ForDataDiff)"
        $tempDestPath = "$($Options.OutputLocation)\DatabaseScripts\Tables"
        if ((Test-Path -Path "$($tempSrcPath)") -and (Test-Path -Path "$($tempDestPath)"))
        {
            $StaticDataCopyStarted = "`r`n`r`n`t`t----- Started collecting static data -----`r`n" +
                        "`t`t------------------------------------------`r`n"
            Out-File -FilePath $Options.OutputLogFile -InputObject $StaticDataCopyStarted -Append

            Copy-Item "$($global:StaticDataPath_ForDataDiff)" -Destination "$($Options.OutputLocation)\DatabaseScripts\Tables" -Recurse

            #Edit permissions to be able to delete later
            $Acl = Get-Acl "$($tempDestPath)\StaticData"
            $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($env:UserName,"FullControl","Allow")
            $Acl.SetAccessRule($Ar)
            Set-Acl "$($tempDestPath)\StaticData" $Acl
        }
    }


    $info = "`r`n`r`n`t`t----- Completed collecting static data -----`r`n" +
                    "`t`t--------------------------------------------"
    Out-File -FilePath $Options.OutputLogFile -InputObject $info -Append
    #endregion

    $info = "`r`n`r`n`t----- Completed scripting the database -----`r`n" +
                    "`t--------------------------------------------`r`n`r`n"
	Out-File -FilePath $Options.OutputLogFile -InputObject $info -Append
}

function Invoke-ApexSqlPackageStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,
        [Parameter(Mandatory = $false)]
        [switch] $Publish,
        [string]$nugetVersion = "",
        [string]$nugetId = $global:nugetId,
        [string]$nugetAuthors = $global:nugetAuthors,
        [string]$nugetOwners = $global:nugetOwners,
        [string]$nugetReleaseNotes = "",
        [string]$apiKey = $global:apiKey,
        [string]$apiKeyFile = $global:apiKeyFile,
        [string]$pushSource = $global:pushSource,
        [string]$nuget = $global:nugetExePath,
        [bool]$clean = $false,
        [switch]$DoNotRemoveContents,
        [switch]$Consolidate,
        [Parameter(Mandatory = $false)]
        [ApexSqlDatabaseConnection] $Database
	)

    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tPackage`r`n"
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Skipping ApexSQL Package step due to failure in the pipeline"
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

    $info = "`r`n`r`n=============================`r`n" +
                    "----- Started Packaging -----`r`n" +
                    "-----------------------------`r`n"
	Out-File -FilePath $Options.OutputLogFile -InputObject $info -Append

    #Script out temp. db to script folder (including static data)
    if ($null -ne $Database)
    {
        Invoke-ApexSqlScriptStep -Options $options -Database $Database | Out-Null
    }

    $ErrorActionPreference = "Stop"
    $global:nugetExe = ""

    RemoveSnapshots -Location "$($Options.OutputLocation)"
    CleanUp
    PackageTheSpecification
    if (($apiKey -eq "" -or $null -eq $apiKey) -and ($null -ne $apiKeyFile -and $apiKeyFile -ne ""))
    {
        $apiKey = (Get-Pass -PasswordFile $apiKeyFile)
    }
    if ($Publish -and $Options.Result -ne "Failure")
    {
        PublishPackage -Destination $Options.OutputLocation -ApiKey $apiKey
    }
    else
    {
        $msg = "`r`n----------`r`n`r`n`tNo publishing."
        Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append
    }

    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }

    #Write step result
    if ($Options.Result -eq "Success")
    {
        $stepName = "Package"
        $msg = "$stepName step passed."
        Write-Verbose $msg
        Out-File -FilePath $Options.OutputLogFile -InputObject "`r`n##### $($msg) #####`r`n" -Append
    }
}

function Invoke-ApexSqlNotifyStep
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,
        [Parameter(Mandatory = $true)]
        [string[]] $DistributionList,
        [Parameter(Mandatory = $true)]
        [ValidateSet("started", "completed", "in progress")]
        [string] $Status,
        [string] $Subject,
        [string] $Body,
        [string] $FailureEnumeration,
        [int] $RetryCount = 3
    )
    if (-not $Subject)
    {
        $Subject = "%PipelineName% pipeline notification: %Status% at %DateTime%"
        if ($Status -ne "started")
        {
           $Subject += " with result: %Result%"
        }
    }
    if (-not $FailureEnumeration)
    {
        $FailureEnumeration = "%FailedSteps% with error code: %ErrorCodes%`r`n"
    }

    [bool] $pipelineResult = $true
    $stepList = ""
    for ($i=0; $i -lt $global:ResultSet.Count; $i++)
    {
        $stepList += "$($global:ResultSet[$i]["Step"])`r`n"
        $stepList += "`tstatus:`t$($global:ResultSet[$i]["Result"])`r`n" +
                    (&{if ($($global:ResultSet[$i][1]) -eq "Failure") {"`t$(GetToolName $($global:ResultSet[$i]["Step"])) return code is: $($global:ResultSet[$i]["ErrorCode"])`r`n"} Else {""}}) +
                    (&{if ($global:ResultSet[$i]["OutputFiles"].Length -gt 0) {"`toutput:`t$($global:ResultSet[$i]["OutputFiles"])`r`n`r`n"} Else {"`r`n"}})
        if ($($global:ResultSet[$i]["Result"]) -eq "Failure")
        {
            $pipelineResult = $false
        }
    }

    $pipelineStarted = "$($Options.Timestamp.remove(2, 1).insert(2, "/").remove(5, 1).insert(5, "/").remove(10, 1).insert(10, " ").replace("-",":"))"
    $pipelineCompleted = Get-Date -Format "MM/dd/yyyy HH:mm:ss"

    $pipelineResultReport = @{$true = "Success"; $false = "Failure" }[$pipelineResult]
    $log = "Name: $($Options.PipelineName)`r`n`r`n"
    $pipelineReturnCode = @{$true = "0"; $false = "1" }[$pipelineResult]

    $log += "Started at $($pipelineStarted)`r`n"
    $log += "Completed at $($pipelineCompleted) with result: $($pipelineResultReport)`r`n"
    $log += "Return code is: $($pipelineReturnCode)`r`n`r`n"

    if ($null -ne $Options.FailedSteps)
    {
        $log += "Failed step:`r`n $($Options.FailedSteps) with error code: $($Options.ErrorCodes)`r`n`r`n"
    }

    $log += "Output files path: $($Options.OutputLocation)`r`n`r`n"



    $log += "`r`n`r`nPipeline steps:`r`n`r`n"
    $log += $stepList

    if ($null -ne $global:SkippingList)
    {
        $log += "`r`n==========`r`n`r`nSkipped steps:`r`n`r`n$($global:SkippingList)"
    }

    $log += "`r`n==========`r`n
            For more details check the $($Options.PipelineName)_job_summary.log file in attachment."


    $Body = "<HTML><HEAD><META http-equiv=""Content-Type"" content=""text/html; charset=iso-8859-1"" /><TITLE></TITLE></HEAD><BODY><p>"
    if ($Status -eq "started")
    {
        $Body = "%PipelineName% %Status% at %DateTime% " -replace "%PipelineName%" ,$Options.PipelineName `
                -replace "%Status%", $Status `
                -replace "%DateTime%", (&{ If ($Status -eq "started") { "$($pipelineStarted)" } Else { "$($pipelineCompleted)" }}) `
    }
    else
    {
        $Body += $log.Replace("`r`n","<br>").Replace("`t","&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
    }

    $Body += "</p></BODY></HTML>"

    $Subject = $Subject -replace "%PipelineName%", $Options.PipelineName `
        -replace "%Status%", $Status `
        -replace "%DateTime%", (&{ If ($Status -eq "started") { "$($pipelineStarted)" } Else { "$($pipelineCompleted)" }}) `
        -replace "%Result%", $Options.Result `
        -replace "%ErrorNum%", $Options.LastExitCode
    if (-not $Options.FailedSteps)
    {
        $failures = "N/A"
    }
    else
    {
        for ($i = 0; $i -lt $Options.FailedSteps.Count; $i++)
        {
            $failures += $FailureEnumeration -replace "%FailedSteps%",$Options.FailedSteps[$i] `
            -replace "%ErrorCodes%",$Options.ErrorCodes[$i]
        }
    }
    $fullBody = $Body
    $mailprops=@{
        Subject = $Subject
        Body = $fullBody
        To = $DistributionList
        From = $Options.NotificationSettings.Credential.UserName
        SmtpServer = $Options.NotificationSettings.SmtpServer
        UseSsl = $Options.NotificationSettings.UseSSL
        Port = $Options.NotificationSettings.Port
        Credential = $Options.NotificationSettings.Credential
        Attachment = $Options.OutputLogFile
    }
    for ($i = 0; $i -lt $RetryCount; $i++)
    {
        try
        {
            Send-MailMessage @mailprops -BodyAsHtml -ErrorAction:Stop
            $response = $null
            break
        }
        catch
        {
            $response = "`r`nNotification step failed after $RetryCount retries with message:`r`n$($_.Exception)"
        }
    }

    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }

    #if ($response)
    #{
	#	Out-File -FilePath $Options.OutputLogFile -InputObject $response -Append
    #}

    if($Status -ne "start")
    {
        #Play beep sound
        [System.Media.SystemSounds]::Beep.Play()
        #Write step result
        ######if ($Options.Result -eq "Success")
        #####{
        #####    $stepName = "Notify"
        #####    $msg = "$stepName step passed."
        #####    Write-Verbose $msg
            #Out-File -FilePath $Options.OutputLogFile -InputObject "`r`n##### $($msg) #####`r`n" -Append
        #####}
    }
    Write-Verbose("`r`n`r`n-----`r`n`r`n`r`n$($log)")
}

function Invoke-ApexSqlDocumentStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

		[Parameter(Mandatory = $false)]
		[ApexSqlDatabaseConnection] $Database,

		[Parameter(Mandatory = $true, ParameterSetName = "pdf")]
        [switch] $AsPdf,

		[Parameter(Mandatory = $true, ParameterSetName = "chm")]
        [switch] $AsChm,

        [Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true,

		[Parameter(Mandatory = $false)]
		[string] $ProjectFile,

		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions,

        [Parameter(Mandatory = $false)]
		[switch] $Differential
	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tDocument`r`n"
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Skipping ApexSQL Document step due to failure in the pipeline"
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }
	
    $project = Set-ProjectSwitch -Options $Options -ProjectFile $ProjectFile
    $additional = Set-AdditionalSwitch -Additional $AdditionalOptions

    #Output files names
    $sourceSwitches = ""
    $sourceSnapShot = ""
    $dbName = ""
    if ($null -ne $Database.ConnectionName)
    {
        $dbName = $Database.ConnectionName
    }
    else
    {
        $dbName = "Database"
    }
    if (!$Differential)
    {
        $reportName = "Document.$($PsCmdlet.ParameterSetName)"
        if ($null -eq $Database)
        {
            $sourceSwitches = "/dbsnp:""$($Options.OutputLocation)\Db_SnapShot.axsnp"""
        }
        else
        {
            $sourceSwitches = "$($Database.AsParameters("doc"))"
        }
    }
    else
    {
        $reportName = "DifferentialDocument.$($PsCmdlet.ParameterSetName)"
        $sourceSwitches  = "/dbsnp:""$($Options.OutputLocation)\Db_SnapShot_Diff.axdsn"""
    }

    #Full tool parameters $($Database.AsParameters("doc"))
	$toolParameters = " /ot:$($PsCmdlet.ParameterSetName) /od:""$($Options.OutputLocation)""" +
	" /on:$reportName $project $additional $sourceSwitches   /v /f"
	$params = @{
		ToolName = "Doc"
		ToolParameters = $toolParameters
		Options = $Options
		StopOnFail = $StopOnFail
        OutputFiles = $reportName
	}

    #Execute the tool
	Start-ApexSQLTool @params

    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
}

function Invoke-ApexSqlSchemaSyncStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,
		[Parameter(Mandatory = $false)]
		[ApexSqlConnection] $Source,
        [Parameter(Mandatory = $false)]
        [ApexSqlConnection] $Target,
		[Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true,
		[Parameter(Mandatory = $false)]
		[string] $ProjectFile,
		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions,
        [Parameter(Mandatory = $false)]
		[switch] $NoReport,
        [Parameter(Mandatory = $false)]
		[switch] $NoScript,
        [Parameter(Mandatory = $false)]
		[switch] $SourceFromPipeline

	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tSchemaSync`r`n"
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Skipping ApexSQL Schemasync step due to failure in the pipeline"
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

	$project = Set-ProjectSwitch -Options $Options -ProjectFile $ProjectFile -ReviewStep
    $additional = Set-AdditionalSwitch -Additional $AdditionalOptions

    #Output files names
    $schemaSyncScript  = "$($Options.OutputLocation)\SchemaSync.sql"
    $schemaSyncReport  = "$($Options.OutputLocation)\SchemaReport.html"


    $srcDefined = (&{ if ($Source) {$true} Else {$false}} )
    $dstDefined = (&{ if ($Target) {$true} Else {$false}} )

    #Check if source is .nupkg
    $sourceParameters = ""
    if (!$SourceFromPipeline)
    {
        if ($Source.NugetID)
        {
            if (-not ($Source.Version.Length -gt 0))
                    {
            ExtractNupkg -OutputLocation $Options.OutputLocation -NugetID $Source.NugetID -Source $Source.Source
        }
            else
                    {
            ExtractNupkg -OutputLocation $Options.OutputLocation -NugetID $Source.NugetID -Version $Source.Version -Source $Source.Source
        }


            $dir = Get-ChildItem $Options.OutputLocation | Where-Object{ $_.PSIsContainer } | Sort-Object LastWriteTime | Select-Object -last 1 | Select-Object -ExpandProperty FullName

            #Clear all files and folders except DatabaseScripts (which should be used as source)
            if($null -ne $dir)
            {
                ClearExtractedContents -path $dir
            }

            $SFPath = Get-ChildItem $dir | Where-Object{ $_.PSIsContainer } | Where-Object{ $_.Name -like "*DatabaseScripts*" } | Select-Object -ExpandProperty FullName | Select-Object -Last 1
            $sourceParameters = " /sf1:""$($SFPath)"" "
            $global:nugetDatabaseScriptsSource = $sourceParameters
        }
        else
        {
            if ($srcDefined)
            {
                $sourceParameters = "$($Source.AsParameters("diff1"))"
            }
        }
    }
    else
    {
        $sourceParameters = " /sf1:""$($Options.OutputLocation)\DatabaseScripts"" "
    }


    if ($dstDefined)
    {
        $targetParameters =  $($Target.AsParameters("diff2"))
    }
    else
    {
        $targetParameters = ""
    }

    #Full tool parameters for silent execution
    $toolParameters = "$($sourceParameters) /sn2:""$($Options.OutputLocation)\Db_SnapShot.axsnp"" /export /v /f"
	$params = @{
		ToolName = "Diff"
		ToolParameters = $toolParameters
		Options = $Options
		StopOnFail = $StopOnFail
        Silent = $true
	}

    #Silent execute the tool
	Start-ApexSQLTool @params


    #Define outputs for tool parameters
    #region tool parameters outputs
    $OutputFiles = ""
    $script = ""
    if (!$NoScript)
    {
        $script = " /ot2:sql /on2:""$schemaSyncScript"""
        $OutputFiles += if ($OutputFiles.Length -gt 0) {", SchemaSync.sql"} else {"SchemaSync.sql"}
    }
    $report = ""
    if (!$NoReport)
    {
        $report = " /ot:html /on:""$schemaSyncReport"""
        $OutputFiles += if ($OutputFiles.Length -gt 0) {", SchemaReport.html"} else {"SchemaReport.html"}
    }
    #endregion

    #Full tool parameters
    $toolParameters = "$($sourceParameters) $($targetParameters) $report $script $project $additional /dsn:""$($Options.OutputLocation)\Db_SnapShot_Diff.axdsn"" /v /f"
	$params = @{
		ToolName = "Diff"
		ToolParameters = $toolParameters
		Options = $Options
		StopOnFail = $StopOnFail
        OutputFiles = if ($OutputFiles.Length -gt 0) {$OutputFiles} else {$null}
	}

    #Execute the tool
	Start-ApexSQLTool @params

    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
}

function Invoke-ApexSqlDataSyncStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,
		[Parameter(Mandatory = $false)]
		[ApexSqlConnection] $Source,
        [Parameter(Mandatory = $false)]
        [ApexSqlConnection] $Target,
		[Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true,
		[Parameter(Mandatory = $false)]
		[string] $ProjectFile,
		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions,
        [Parameter(Mandatory = $false)]
		[switch] $NoReport,
        [Parameter(Mandatory = $false)]
		[switch] $NoScript,
        [Parameter(Mandatory = $false)]
		[switch] $SourceFromPipeline
	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tDataSync`r`n"
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Skipping ApexSQL DataSync step due to failure in the pipeline"
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

    $project = Set-ProjectSwitch -Options $Options -ProjectFile $ProjectFile -ReviewStep
    $additional = Set-AdditionalSwitch -Additional $AdditionalOptions

    #Output files names
    $dataSyncScript  = "DataSync.sql"
    $dataSyncReport  = "DataReport.html"

    $sourceParameters = ""
    if (!$SourceFromPipeline)
    {
        #Check if .nupkg sources is already configured
        if ($null -ne $global:nugetDatabaseScriptsSource)
        {
            $sourceParameters = $global:nugetDatabaseScriptsSource
        }
        else
        {
            #Check if source is .nupkg
            if ($Source.NugetID)
            {
                ExtractNupkg -OutputLocation $Options.OutputLocation -NugetID $Source.NugetID -Version $Source.Version -Source $Source.Source
                $dir = Get-ChildItem $Options.OutputLocation | Where-Object{ $_.PSIsContainer } | Sort-Object LastWriteTime | Select-Object -last 1 | Select-Object -ExpandProperty FullName

                #Clear all files and folders except DatabaseScripts (which should be used as source)
                if($null -ne $dir)
                {
                    ClearExtractedContents -path $dir
                }
                $SFPath = Get-ChildItem $dir | Where-Object{ $_.PSIsContainer } | Where-Object{ $_.Name -like "*DatabaseScripts*" } | Select-Object -ExpandProperty FullName | Select-Object -Last 1
                $sourceParameters = " /sf1:""$($SFPath)"" "
            }
            else
            {
                $sourceParameters = "$($Source.AsParameters("diff1"))"
            }
        }
    }
    else
    {
        $sourceParameters = " /sf1:""$($Options.OutputLocation)\DatabaseScripts"" "
    }

    #Define outputs for tool parameters
    #region tool parameters outputs
    $OutputFiles = ""
    $report = ""
    if (!$NoReport)
    {
        $report = " /ot:html /on:""$dataSyncReport"""
        $OutputFiles += if ($OutputFiles.Length -gt 0) {", DataReport.html"} else {"DataReport.html"}
    }
    $script = ""
    if (!$NoScript)
    {
        $script = " /ot2:sql /on2:""$dataSyncScript"""
        $OutputFiles += if ($OutputFiles.Length -gt 0) {", DataSync.sql"} else {"DataSync.sql"}
    }
    #endregion

    #Full tool parameters
    $toolParameters = "$($sourceParameters) $($Target.AsParameters("diff2")) $report $script $project$additional /v /f"
	$params = @{
		ToolName = "Data Diff"
		ToolParameters = $toolParameters
		Options = $Options
		StopOnFail = $StopOnFail
        OutputFiles = if ($OutputFiles.Length -gt 0) {$OutputFiles} else {$null}
	}

    #Execute the tool
	Start-ApexSQLTool @params
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
}

function Invoke-ApexSqlDeployStep
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

        [Parameter(Mandatory = $false)]
		[ApexSqlConnection] $Source,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Schema", "Data", "Both")]
        [string] $DeployType,

        [Parameter(Mandatory = $false)]
        [switch] $UseCurrentPackage,

        [Parameter(Mandatory = $true)]
        [ApexSqlDatabaseConnection[]] $Databases
    )

    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tDeploy`r`n"
        LogFail -FilePath $Options.OutputLogFile -ErrorText "Skipping ApexSQL Deploy step due to failure in the pipeline"
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

    $info = "`r`n`r`n=============================`r`n" +
                    "----- Started Deploying -----`r`n" +
                    "-----------------------------`r`n"
	Out-File -FilePath $Options.OutputLogFile -InputObject $info -Append

    try
    {
        if ($UseCurrentPackage)
        {
            $PackageFilePath = $Options.PackageFilePath
            ExtractNupkg -NugetID $global:nugetId -Source $Options.OutputLocation -OutputLocation "$($Options.OutputLocation)\"

        }
        else
        {
            if ($null -ne $Source.Version)
            {
                ExtractNupkg -NugetID $Source.NugetID -Source $Source.Source -OutputLocation $Options.OutputLocation
            }
            else
            {
                ExtractNupkg -NugetID $Source.NugetID -Source $Source.Source -Version $Source.Version -OutputLocation $Options.OutputLocation
            }

        }


        $lookAtDir = $null
        if(!$UseCurrentPackage)
        {
             $lookAtDir = $Options.OutputLocation
        }
        else
        {
            $lookAtDir = Get-ChildItem $Options.OutputLocation | Where-Object{ $_.PSIsContainer } | Sort-Object LastWriteTime | Select-Object -last 1 | Select-Object -ExpandProperty FullName
        }


        $lookAtDir = Get-ChildItem -Path $Options.OutputLocation
        $schemaScripts = $lookAtDir | Where-Object -FilterScript {$_.Name -like "SchemaSync.sql"}
        $dataScripts   = $lookAtDir | Where-Object -FilterScript {$_.Name -like "DataSync.sql"}
        $consolidatedScript   = $lookAtDir | Where-Object -FilterScript {$_.Name -like "*Consolidated_script.sql"}
        $schemaOK = ($DeployType -eq "Schema") -and ($schemaScripts.Count -eq 1) -and $consolidatedScript.Count -eq 0
        $dataOK   = ($DeployType -eq "Data") -and ($dataScripts.Count -eq 1) -and $consolidatedScript.Count -eq 0
        $bothOK   = ($DeployType -eq "Both") -and ($schemaScripts.Count -eq 1 -or $dataScripts.Count -eq 1 -or $consolidatedScript.Count -eq 1 )

        if (($schemaOK -eq $false -and $dataOK -eq $false) -and $bothOK -eq $false)
        {
            $errorText = "There are no schema or data differences.`r`n" +
            "`tProcess terminated."
            LogFail -FilePath $Options.OutputLogFile -ErrorText $errorText
            $Options.ErrorCodes += 102
            $Options.FailedSteps += @("ApexSQL Deploy")
            $Options.Result = "Failure"
            $global:ResultSet.Add($global:ResultSet.Count, @{Step="Deploy"; Result='Failure'; ErrorCode=$lastExitCode;})
            return
        }

        foreach ($database in $Databases)
        {
            if ($database.WindowsAuthentication)
            {
                $credentials = " -E"
            }
            else
            {
                $credentials = " -U ""$($database.UserName)"" -P ""$($database.Password)"""
            }
            $sqlcmdProps = "sqlcmd.exe -S ""$($database.Server)"" -d ""$($database.Database)""$credentials -b -i"

            if (($schemaOK -or $bothOK) -and $null -ne $schemaScripts)
            {
                $schema = $schemaScripts[0].FullName
                $result = Invoke-Expression -Command "$sqlcmdProps ""$schema"""
                Out-File -FilePath $Options.OutputLogFile -InputObject $result -Append
                if ($LastExitCode -ne 0)
                {
                    $Options.ErrorCodes += @($LastExitCode)
                    $Options.FailedSteps += @("ApexSQL Deploy")
                    $Options.Result = "Failure"
                    throw "Schema synchronization failed"
                }
            }
            if (($dataOK -or $bothOK)  -and $null -ne $dataScripts)
            {
                $data = $dataScripts[0].FullName
                $result = Invoke-Expression -Command "$sqlcmdProps ""$data"""
                Out-File -FilePath $Options.OutputLogFile -InputObject $result -Append
                if ($LastExitCode -ne 0)
                {
                    $Options.ErrorCodes += @($LastExitCode)
                    $Options.FailedSteps += @("ApexSQL Deploy")
                    $Options.Result = "Failure"
                    throw "Data synchronization failed"
                }
            }
        }

        #Write step result
        $stepName = "Deploy"
        LogFail -FilePath $Options.OutputLogFile -ErrorText "$stepName step passed."
        $global:ResultSet.Add($global:ResultSet.Count, @{Step="Deploy"; Result='Success';})
    }
    catch
    {

		$Options.FailedSteps += @("ApexSQL Deploy")
        $Options.ErrorCodes += @($lastExitCode)
		if ($StopOnFail)
		{
            $stepName = "Deploy"
			$Options.Result = "Failure"
            $msg = "$stepName step failed."
            Write-Warning $msg
            LogFail -FilePath $Options.OutputLogFile -ErrorText "`r`nApexSQL $ToolName failed.`r`nThe process is canceled due to failure return code: $lastExitCode"
            return $false
		}
		else
		{
			$Options.Result = "Completed with errors"
		}

        Out-File -FilePath $Options.OutputLogFile -InputObject $_.Message -Append
    }
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }

}
