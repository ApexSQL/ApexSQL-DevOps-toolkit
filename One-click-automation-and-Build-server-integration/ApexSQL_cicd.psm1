#region Classes
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
        [string] $UserName,

        [Parameter(Mandatory = $false, ParameterSetName = "credentials")]
        [string] $Password
    )
    $connection = New-Object -TypeName ApexSqlDatabaseConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Server   = $Server
    $connection.Database = $Database
    $connection.WindowsAuthentication = $WindowsAuthentication
    $connection.UserName = $UserName
    $connection.Password = $Password
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
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $ConnectionName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("tfs","git","mercurial", "subversion", "perforce", "file", "nuget")]
        [String] $Source_Type,

        [Parameter(Mandatory = $false)]
        [string] $UserName,

        [Parameter(Mandatory = $false)]
        [string] $Password,

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

     $global:scRepoConnectionName = $ConnectionName

    if ($Source_Type -ne $null)
    {
        switch($Source_Type)
        {
            "tfs" { New-ApexSqlTfsSourceControlConnection -ConnectionName $ConnectionName -Server $Server -Project $Project -Label $Label -UserName $UserName -Password $Password }
            "git" { New-ApexSqlGitSourceControlConnection -ConnectionName $ConnectionName -Repository $Repository -Project $Project -Branch $Branch -Label $Label -UserName $UserName -Password $Password }
            "mercurial" { New-ApexSqlMercurialSourceControlConnection -ConnectionName $ConnectionName -Repository $Repository -Project $Project -Label $Label -UserName $UserName -Password $Password }
            "subversion" { New-ApexSqlSubversionSourceControlConnection -ConnectionName $ConnectionName -Repository $Repository -Project $Project -Label $Label -UserName $UserName -Password $Password  }
            "perforce" { New-ApexSqlPerforceSourceControlConnection -ConnectionName $ConnectionName -Server $Server -Repository $Repository -Project $Project -Label $Label -UserName $UserName -Password $Password }
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
        [string] $UserName,

        [Parameter(Mandatory = $true)]
        [string] $Password
    )

    $connection = New-Object ApexSqlSourceControlConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Source_Type = "git"
    $connection.Repository = $Repository
    $connection.Project = $Project
    $connection.Branch = $Branch
    $connection.Label = $Label
    $connection.UserName = $UserName
    $connection.Password = $Password
    return $connection
}

function New-ApexSqlTfsSourceControlConnection
{
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
        [string] $UserName,

        [Parameter(Mandatory = $true)]
        [string] $Password
    )

    $connection = New-Object ApexSqlSourceControlConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Source_Type = "teamfoundationserver"
    $connection.Server = $Server
    $connection.Project = $Project
    $connection.Label = $Label
    $connection.UserName = $UserName
    $connection.Password = $Password
    return $connection
}

function New-ApexSqlMercurialSourceControlConnection
{
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
        [string] $UserName,

        [Parameter(Mandatory = $true)]
        [string] $Password
    )

    $connection = New-Object ApexSqlSourceControlConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Source_Type = "mercurial"
    $connection.Repository = $Repository
    $connection.Project = $Project
    $connection.Label = $Label
    $connection.UserName = $UserName
    $connection.Password = $Password
    return $connection
}

function New-ApexSqlSubversionSourceControlConnection
{
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
        [string] $UserName,

        [Parameter(Mandatory = $true)]
        [string] $Password
    )

    $connection = New-Object ApexSqlSourceControlConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Source_Type = "subversion"
    $connection.Repository = $Repository
    $connection.Project = $Project
    $connection.Label = $Label
    $connection.UserName = $UserName
    $connection.Password = $Password
    return $connection
}

function New-ApexSqlPerforceSourceControlConnection
{
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
        [string] $UserName,

        [Parameter(Mandatory = $true)]
        [string] $Password
    )

    $connection = New-Object ApexSqlSourceControlConnection
    $connection.ConnectionName = $ConnectionName
    $connection.Source_Type = "perforce"
    $connection.Server = $Server
    $connection.Repository = $Repository
    $connection.Project = $Project
    $connection.Label = $Label
    $connection.UserName = $UserName
    $connection.Password = $Password
    return $connection
}

class ApexSqlFileConnection : ApexSqlConnection
{
    [string] $FilePath
}

function New-ApexSqlFileConnection
{
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
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $EmailAddress,

        [Parameter(Mandatory = $false)]
        [string] $Password,

        [Parameter(Mandatory = $true)]
        [string] $SmtpServer,

        [Parameter(Mandatory = $true)]
        [int]    $Port,

        [Parameter(Mandatory = $false)]
        [switch] $UseSSL
    )
    if ($Password -ne $null -and $Password -ne '')
    {
        $pass = $Password | ConvertTo-SecureString -AsPlainText -Force
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
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $PipelineName,

        [Parameter(Mandatory = $false)]
        [string] $OutputLocation,

        [Parameter(Mandatory = $true)]
        [ApexSqlNotificationSettings] $NotificationSettings,

        [Parameter(Mandatory = $false)]
        [switch] $NoSubfolders
    )
    $timestamp = Get-Date -Format "MM-dd-yyyy_HH-mm-ss"

    $options = New-Object -TypeName ApexSqlOptions
    $options.PipelineName = $PipelineName
    $options.ScriptDirectory = $global:currentDirectory

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
    $options.NotificationSettings = $NotificationSettings
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

function GetSourceName
{
    [CmdletBinding()]
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

function GetSourceForDataDiff
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true)]
        [xml] $xml,

        [Parameter(Mandatory = $true)]
        [string] $scPass
    )

        $sct1 = GetSourceName ($xml.ApexSQLBuildProject.ProjectOptions.Options.Option.ScConnectionInfo.SourceControlType)
        $scs1 = "$($xml.ApexSQLBuildProject.ProjectOptions.Options.Option.ScConnectionInfo.Server)"
        $scj1 = "$($xml.ApexSQLBuildProject.ProjectOptions.Options.Option.ScConnectionInfo.ProjectPath)"
        $scr1 = "$($xml.ApexSQLBuildProject.ProjectOptions.Options.Option.ScConnectionInfo.Repository)"
        $scb1 = "$($xml.ApexSQLBuildProject.ProjectOptions.Options.Option.ScConnectionInfo.Branch)"
        $scl1 = "$($xml.ApexSQLBuildProject.ProjectOptions.Options.Option.ScConnectionInfo.Label)"
        $scf1 = "$($xml.ApexSQLBuildProject.ProjectOptions.Options.Option.ScConnectionInfo.CustomScriptsFolderLocation)"
        $scu1 = "$($xml.ApexSQLBuildProject.ProjectOptions.Options.Option.ScConnectionInfo.UserName)"
        $scp1 = $scPass
         
        $DataDiffParameters = " /sct1:$($sct1) "

        if ($sct1 -eq "teamfoundationserver")
        {
            if ($scs1 -ne $null -and $scs1 -ne "")
            {
                $DataDiffParameters += " /scs1:""$($scs1)"" "
            }
            if ($scj1 -ne $null -and $scj1 -ne "")
            {
                $DataDiffParameters += " /scj1:""$($scj1)"" "
            }
            if ($scb1 -ne $null -and $scb1 -ne "")
            {
                $DataDiffParameters += " /scb1:""$($scb1)"" "
            }
            if ($scl1 -ne $null -and $scl1 -ne "")
            {
                $DataDiffParameters += " /scl1:""$($scl1)"" "
            }  
        }
        if ($sct1 -eq "git" -or $sct1 -eq "mercurial")
        {
            if ($scs1 -ne $null -and $scs1 -ne "" -and $scr1 -ne $null -and $scr1 -ne "")
            {
                $DataDiffParameters += " /scr1:""$($scs1)/$($scr1)"" "
            }
            if ($scj1 -ne $null -and $scj1 -ne "")
            {
                $DataDiffParameters += " /scj1:""$($scj1)"" "
            }
            if ($scb1 -ne $null -and $scb1 -ne "")
            {
                $DataDiffParameters += " /scb1:""$($scb1)"" "
            }
            if ($scl1 -ne $null -and $scl1 -ne "")
            {
                $DataDiffParameters += " /scl1:""$($scl1)"" "
            } 
        }
        if ($scu1 -ne $null -and $scu1 -ne "")
        {
            $DataDiffParameters += " /scu1:""$($scu1)"" "
        }
        if ($scp1 -ne $null -and $scp1 -ne "")
        {
            $DataDiffParameters += " /scp1:""$($scp1)"" "
        }

        return $DataDiffParameters
}
#endregion

#region Helpers

function Initialize-Globals
{
	param
    (
        [string] $CurrentDirectory
    )
    $global:currentDirectory = $CurrentDirectory
    $global:logPath = $null
    $global:SourceForScriptDataDiff = $null
    $global:SkippingList = $null
    $global:nuspec = $null
    $global:nugetDbScriptFolderSource = $null
    $global:qaDB = $null
    #Create and reset ResultSet
    $global:ResultSet = [ordered]@{}
    if ($Options.Result -eq $null)
    {
        $global:ResultSet.Clear()
    }    
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
        "SchemaSync" {return "ApexSQL Diff"}
        "DataSync" {return "ApexSQL Data Diff"}
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
        "Diff" {return "SchemaSync"}
        "Data Diff" {return "DataSync"}
        "Package" {return "Package"}
        "Deploy" {return "Deploy"}
        default {return}
    }
}

function Get-ApexSQLToolLocation
{
    param
    (
        [Parameter(Mandatory = $true)]
        [String] $ApplicationName
    )
    $key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ApexSQL $($ApplicationName)_is1"
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
		[bool] $Silent
	)
    

	$logFile = "$OutputLocation\$($PipelineName).log"
    
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
	
	if ($lastExitCode -ne 0 -and ($lastExitCode -ne 102 -and $ToolName -eq "Generate")) 
	{
		$Options.FailedSteps += @("ApexSQL $ToolName")
        $Options.ErrorCodes += @($lastExitCode)
		if ($StopOnFail)
		{
			$error = "`r`nApexSQL $ToolName failed.`r`nThe process is canceled due to failure return code: $lastExitCode"
			Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append
			$Options.Result = "Failure"
            return $false
		}
		else
		{
			$Options.Result = "Completed with errors"
		}
	}
    else
    {
        if ($ToolName -ne "Script" -and $Silent -ne $true -and ($FromPackage -eq $true -and $ToolName -eq "Data Diff") -ne $true)
        {

            $stepName = GetStepName -Tool $ToolName
            $msg = "$stepName step passed."
            Write-Host $msg
            Out-File -FilePath $Options.OutputLogFile -InputObject "`r`n##### $($msg) #####`r`n" -Append

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
        # Assumption, nuget.exe is the current folder where this file is.
        $global:nugetExe = Join-Path $source "nuget" 
    }

    $global:nugetExe

    if (!(Test-Path $global:nugetExe -PathType leaf))
    {
        $error = "'nuget.exe' file was not found. Please provide correct 'nuget.exe' file path.`r`nProces terminated."
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject "`r`n`t$($error)" -Append
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
    #Copy .nuspec file as template to output directory
    Copy-Item "C:\Program Files\ApexSQL\ApexSQL CICD toolkit\Modules\ApexSQL_cicd\Package.nuspec" $Options.OutputLocation

    $shema = $null
    $data = $null
    $consolidatedScript = "$($Options.OutputLocation)\Consolidated_script.sql" 
    if ($Consolidate)
    {
        $shema = Get-ChildItem -Path $Options.OutputLocation -Filter SchemaSync_*.sql
        $data =Get-ChildItem -Path $Options.OutputLocation -Filter DataSync_*.sql

        if ($shema -ne $null)
        {
            $content += Get-Content -Path "$($Options.OutputLocation)\$shema"
            Remove-Item "$($Options.OutputLocation)\$shema"
        }
        if ($data -ne $null)
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
        &$nugetExe pack $Options.OutputLocation -Properties id=$nugetId -Properties version=$nugetVersion -Properties authors=$nugetAuthors -Properties owners=$nugetOwners -Properties description=$files -Properties releaseNotes=$nugetReleaseNotes -OutputDirectory $Options.OutputLocation
    
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

        $error = "Creating the package failed:`r`n"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject "`t$($error)" -Append 
        $Options.ErrorCodes += @($LASTERRORCODE)
        $Options.FailedSteps += @("ApexSQL Package")
        $Options.Result = "Failure"
        return
    }

    

    #Remove templete .nuspec file
    Remove-Item "$($Options.OutputLocation)\Package.nuspec"
    
    #Get .nupkg file name to add it to $outputs
    $packageName = @(Get-ChildItem "$($Options.OutputLocation)" -Filter *.nupkg)
    $packageName = $packageName.FullName
    $Options.PackageFilePath = $packageName
    
    #If DoNotRemoveContents switch missing remove all files (except .nupkg and .log)
    if (!$DoNotRemoveContents)
    {
        Get-Childitem "$($Options.OutputLocation)" -Exclude *.nupkg, *_job_summary.log | foreach ($_) {remove-item $_.fullname -Recurse }
    }
}

function PublishPackage()
{
    [CmdletBinding()]
	param
    (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string] $Destination
    )

    if ($apiKey -eq "")
    {
        $error = "No NuGet server api key provided - so not pushing anything up."
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append 
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
        $error = "No nupkg files found in the directory: $destination`r`n`tTerminating process."
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject "`t`t$($error)" -Append 
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
            &$nugetExe push ($file.FullName) -Source $pushSource -apiKey $apiKey

            $msg = "`r`n`tPackage successfully published."
            Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append

        }
        catch
        {
            $error = "`tPackage publishing failed: `r`n`t`t>>$($_.Exception.Message)<<"
            Write-Warning -Message $error
            Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append 
            $Options.ErrorCodes += @($LastExitCode)
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
    if (-Not $Version)
    {
        try
        {
            &$nuget install $NugetID -Output $OutputLocation -Source $Source >> $Options.OutputLogFile
            $msg = "`r`n`tPackage successfully extracted.`r`n`r`n`t----------`r`n"
            Out-File -FilePath $Options.OutputLogFile -InputObject $msg -Append
        }
        catch
        {
            $error = "`tThere was some problem in extracting the .nupkg file.`r`n`t`t>>$($_.Exception.Message)<<"
            Write-Warning -Message $error
            Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append 
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
            $error = "`tThere was some problem in extracting the .nupkg file.`r`n`t`t>>$($_.Exception.Message)<<"
            Write-Warning -Message $error
            Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append 
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

    Get-Childitem $path | where-object {$_.Name -notlike "*DbScriptFolder*"} | foreach ($_) {remove-item $_.fullname -Recurse }
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
        [switch] $NoScript,

        [Parameter(Mandatory = $false)]
        [string] $scPass,

        [Parameter(Mandatory = $false)]
        [string] $dbPass
	)
    if ($Options.Result -eq "Failure")
    {
        $error = "Skipping ApexSQL Build step due to failure in the pipeline"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

    $project = ""
    #If ProjectFile (that means that $Source and $Database are NOT created)
    #$Source doesn't so matter since source details will be picked from project file
    #It is important to create $Database object for further use (next steps)
	if ($ProjectFile)
	{
        $ProjectFile = $options.ScriptDirectory + "\Projects\" + $ProjectFile
        $project = " /project:""$ProjectFile"""

        #Get details from ProjectFile
        [xml] $xml = Get-Content "$($ProjectFile)"
        $global:SourceForScriptDataDiff = GetSourceForDataDiff -xml $xml -scPass "$($scPass)"
	}
    else
    {
        #Store Source for Static Data (from entered parameters)
        $global:SourceForScriptDataDiff = $Source
    }
    
    if (($Source -eq $null -and $Database -eq $null) -and $ProjectFile -eq $null)
    {
        $error = "Source and Database or a Project file must be set"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = " $AdditionalOptions"
	}

    #Configure Source parameters
    $sourceType = "sc"
    if ($Source -ne $null)
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
        $global:SourceForScriptDataDiff = $($sourceParams).replace(":", "1:").replace("http1:","http:").replace("https1:","https:")
    }

    #Configure Database parameters
    $databaseType = "db"
    if ($Database -ne $null)
    {
	    $databaseParams = $Database.AsParameters()
        $global:qaDB = $Database
    } 

    #Output files names
    $connName = @{$true = "Project"; $false = "$($Source.ConnectionName)_$($Database.ConnectionName)" }[!$Source -and !$Database]
    $scriptName = "$($Options.OutputLocation)\Build_$($connName)_BuildScript.sql"

    

    #Full tool parameters
    $outScript = ""
    if (!$NoScript)
    {
        $outScript = " /on:""$($scriptName)"" "
    }
    $toolParameters = 
    @{$true = "/source_type:$sourceType $sourceParams /output_type:$databaseType $databaseParams "; $false = " $project "}[!$ProjectFile] + 
	    " /drop_if_exists $additional $drop  $outScript  /script_permissions /v /f"
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

    #Store output files
    $outputs = ""
    if (!$NoScript)
    {
        $outputs = "$($scriptName)"
    }
    $global:ResultSet.Add($global:ResultSet.Count, @("Build", (&{ if ($Options.Result-ne $null) {"$($Options.Result)"} Else {""}} ), (&{ if ($outputs -ne $null) {"$($outputs)"} Else {""}}), (&{ if ($Options.ErrorCodes -ne $null) {"$($Options.ErrorCodes)"} Else {""}} )))
}

function Invoke-ApexSqlPopulateStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

		[Parameter(Mandatory = $true)]
		[ApexSqlDatabaseConnection] $Database,

        [Parameter(Mandatory = $false)]
        [int] $RowCount = 1000,

        [Parameter(Mandatory = $false)]
        [bool] $FillOnlyEmptyTables = $false,

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
        $error = "Skipping ApexSQL Populate step due to failure in the pipeline"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }
	$project = ""
	if ($ProjectFile)
	{
        $ProjectFile = $options.ScriptDirectory + "\Projects\" + $ProjectFile
        $project = " /project:""$ProjectFile"""
	}
	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = " $AdditionalOptions"
	}
    $fillEmpty = ""
    if ($FillOnlyEmptyTables)
    {
       $fillEmpty = " /foet" 
    }

    #Output files names
    $scriptName = "Populate_$($Database.ConnectionName)_PopulateScript.sql"

    #Full tool parameters
    $outScript = ""
    if (!$NoScript)
    {
        $outScript = "/ot:SQL /on:""$($Options.OutputLocation)\$($scriptName)"""
    }
	$toolParameters = "$($Database.AsParameters()) /r:$($RowCount)$fillEmpty$project$additional $($outScript) /v /f "
	$params = @{
		ToolName = "Generate"
		ToolParameters = $toolParameters 
		Options = $Options
		StopOnFail = $StopOnFail
	}

    #Execute the tool
	Start-ApexSQLTool @params | Out-Null
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }

    #Store output files
    $outputs =""
    if (!$NoScript)
    {
        $outputs += "$($scriptName)"
    }
    $global:ResultSet.Add($global:ResultSet.Count, @("Populate", (&{ if ($Options.Result-ne $null) {"$($Options.Result)"} Else {""}} ), (&{ if ($outputs -ne $null) {"$($outputs)"} Else {""}}), (&{ if ($Options.ErrorCodes -ne $null) {"$($Options.ErrorCodes)"} Else {""}} )))
}

function Invoke-ApexSqlAuditStep
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

		[Parameter(Mandatory = $false)]
		[string] $ProjectFile,

		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions,

        [Parameter(Mandatory = $false)]
		[switch] $NoScript,

        [Parameter(Mandatory = $false)]
		[switch] $NoReport
	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tAudit`r`n"
        $error = "Skipping ApexSQL Audit step due to failure in the pipeline"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }
    $project = ""
    if ($ProjectFile)
    {
        $ProjectFile = $options.ScriptDirectory + "\Projects\" + $ProjectFile
        $project = " /project:""$ProjectFile"""
    }
    $additional = ""
    if ($AdditionalOptions)
    {
       $additional = " $AdditionalOptions"
    }

    #Output files names
    $reportName = "$($Options.OutputLocation)\Audit_$($Database.ConnectionName)_AuditReport.pdf"

    #Full tool parameters
    $outScript = ""
    if (!$NoScript)
    {
        $outScript = ""
    }
    $outReport = ""
    if (!$NoReport)
    {
        $outReport = "/sr /rf:pdf /or:$($reportName)"
    }
    $toolParameters = "$($Database.AsParameters())$project$additional $outReport /ai:a /at /v /f"
    $params = @{
        ToolName = "Trigger"
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

    #Store output files
    $outputs = ""
    if (!$NoScript)
    {
        $outputs += ""
    }
    if (!$NoReport)
    {
        $outputs += $reportName
    }
    $global:ResultSet.Add($global:ResultSet.Count, @("Audit", (&{ if ($Options.Result-ne $null) {"$($Options.Result)"} Else {""}} ), (&{ if ($outputs -ne $null) {"$($outputs)"} Else {""}}), (&{ if ($Options.ErrorCodes -ne $null) {"$($Options.ErrorCodes)"} Else {""}} )))
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
        $error = "Skipping ApexSQL Review step due to failure in the pipeline"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }
	$project = ""
	if ($ProjectFile)
	{
		$ProjectFile = $options.ScriptDirectory + "\Projects\" + $ProjectFile
        $project = " /project:""$ProjectFile"""
	}
    
	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = $AdditionalOptions
	}
    
    #Output files names
    $reportName = "$($Options.OutputLocation)\Review_$($Database.ConnectionName)_ReviewResults.html"
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
        $outReport = "/ot:h /on:$($reportName)"
    }
	$toolParameters = " $($Database.AsParameters()) $($additional) /rb:""$($ProjectFile)"" $($outReport) $($reportContents) /v /f"
	$params = @{
		ToolName = "Enforce"
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

    #Store output files
    $outputs = ""
    if (!$NoReport)
    {
        $outputs = $reportName
    }
    $global:ResultSet.Add($global:ResultSet.Count, @("Review", $($Options.Result), $($outputs), (&{ if ($Options.ErrorCodes -ne $null) {"$($Options.ErrorCodes)"} Else {""}} )))
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
        $error = "Skipping ApexSQL Test step due to failure in the pipeline"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

    #sqlCop to install
	$sqlCop = ""
	if ($InstallSqlCop)
	{
		$sqlCop = " /install_sqlcop"
	}
    
    if ($ProjectFile)
	{
		$ProjectFile = $options.ScriptDirectory + "\Projects\" + $ProjectFile
        $project = " /project:""$ProjectFile"""
	}

	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = " $AdditionalOptions"
	}

    #Output files names
    $testReport = "$($Options.OutputLocation)\Test_$($Database.ConnectionName)_TestResults.xml"

    #Full tool parameters
    $outReport = ""
    if (!$NoReport)
	{
        $outReport = "/or:""$($testReport)""" 
    }
    $toolParameters = "$($Database.AsParameters()) /install_tsqlt $outReport $sqlCop$project$additional /v /f"
	$params = @{
		ToolName = "Unit Test"
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

    #Store output files
    $outputs =""
    if (!$NoReport)
	{
        $outputs += "$($testReport)"  
    }
    $global:ResultSet.Add($global:ResultSet.Count, @("Test", (&{ if ($Options.Result-ne $null) {"$($Options.Result)"} Else {""}} ), (&{ if ($outputs -ne $null) {"$($outputs)"} Else {""}}), (&{ if ($Options.ErrorCodes -ne $null) {"$($Options.ErrorCodes)"} Else {""}} )))
}

function Invoke-ApexSqlScriptStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

		[Parameter(Mandatory = $false)]
		[ApexSqlDatabaseConnection] $Database = $global:qaDB,

        [Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true
	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tScript`r`n"
        $error = "Skipping ApexSQL Script step due to failure in the pipeline"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }

    #Output files names
    $scriptName = "$($Options.OutputLocation)\DbScriptFolder\" #_$($Database.ConnectionName)

    New-Item -ItemType Directory -Path "$($scriptName)" -F
    
    #region Script
    #Full tool parameters
	$toolParameters = " $($Database.AsParameters()) /exc:16384:SQLCop:tSQLt /exc:134217728:tSQLtCLR /eso /in /fl:""$($scriptName)"" /v /f"
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
    $toolParametersDataDiff = " $global:SourceForScriptDataDiff /sf2:""$($scriptName)"" /o:8 /sync /f"
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

    $info = "`r`n`r`n`t`t----- Completed collecting static data -----`r`n" +
                    "`t`t--------------------------------------------"
    Out-File -FilePath $Options.OutputLogFile -InputObject $info -Append
    #endregion

    $info = "`r`n`r`n`t----- Completed scripting the database -----`r`n" +
                    "`t--------------------------------------------`r`n`r`n"
	Out-File -FilePath $Options.OutputLogFile -InputObject $info -Append

    #Store output files
    $outputs = $scriptName
    $global:ResultSet.Add($global:ResultSet.Count, @("Script", (&{ if ($Options.Result-ne $null) {"$($Options.Result)"} Else {""}} ), (&{ if ($outputs -ne $null) {"$($outputs)"} Else {""}}), (&{ if ($Options.ErrorCodes -ne $null) {"$($Options.ErrorCodes)"} Else {""}} )))
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
        [string]$pushSource = $global:pushSource,
        [string]$UserName = $global:userName,
        [string]$Password = $global:password,
        [string]$nuget = $global:nugetExePath,
        [bool]$clean = $false,
        [switch]$DoNotRemoveContents,
        [switch]$Consolidate
	)

    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tPackage`r`n"
        $error = "Skipping ApexSQL Package step due to failure in the pipeline"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append -Confirm:$false
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
    if ($global:qaDB -ne $null)
    {
        Invoke-ApexSqlScriptStep -Options $options | Out-Null
    }

    $ErrorActionPreference = "Stop"
    $global:nugetExe = ""

    RemoveSnapshots -Location "$($Options.OutputLocation)"
    CleanUp
    PackageTheSpecification
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
    if ($Publish)
    {
        PublishPackage -Destination $Options.OutputLocation
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
        $stepName = "Packaging"
        $msg = "$stepName step passed."
        Write-Host $msg
        Out-File -FilePath $Options.OutputLogFile -InputObject "`r`n##### $($msg) #####`r`n" -Append
    }
    $global:ResultSet.Add($global:ResultSet.Count, @("Package", $($Options.Result), "$($Options.PackageFilePath)", (&{ if ($Options.ErrorCodes -ne $null) {"$($Options.ErrorCodes)"} Else {""}} )))
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
        foreach ($item in $global:ResultSet)
        {
            $stepList += "$($item[$i][0])`r`n"
            $stepList += "`tstatus:`t$($item[$i][1])`r`n" +
                    (&{if ($($item[$i][1]) -eq "Failure") {"`t$(GetToolName $($item[$i][0])) return code is: $($item[$i][3])`r`n"} Else {""}}) +
                    (&{if ($item[$i][2]) {"`toutput:`t$($item[$i][2])`r`n`r`n"} Else {"`r`n"}})
            if ($($item[$i][1]) -eq "Failure")
            {
                $pipelineResult = $false
            }
        }
    }

    $pipelineStarted = "$($Options.Timestamp.remove(2, 1).insert(2, "/").remove(5, 1).insert(5, "/").remove(10, 1).insert(10, " ").replace("-",":"))"
    $pipelineCompleted = Get-Date -Format "MM/dd/yyyy HH:mm:ss"

    $pipelineResultReport = @{$true = "Success"; $false = "Failure" }[$pipelineResult]
    $log = "Pipeline name: $($Options.PipelineName)`r`n`r`n"
    $pipelineReturnCode = @{$true = "0"; $false = "1" }[$pipelineResult]
    
    $log += "Pipeline started at $($pipelineStarted)`r`n"
    $log += "Pipeline completed at $($pipelineCompleted) with result: $($pipelineResultReport)`r`n"
    $log += "Pipeline return code is: $($pipelineReturnCode)`r`n`r`n"

    if ($Options.FailedSteps -ne $null)
    {
        $log += "Failed step:`r`n $($Options.FailedSteps) with error code: $($Options.ErrorCodes).`r`n`r`n" 
    }

    $log += "Pipeline output files path: $($Options.OutputLocation)`r`n`r`n"
    
    
    
    $log += "`r`n`r`nPipeline steps:`r`n`r`n"
    $log += $stepList

    if ($global:SkippingList -ne $null)
    {
        $log += "`r`n==========`r`n`r`nSkipped steps:`r`n`r`n$($global:SkippingList)"
    }

    $log += "`r`n==========`r`n
            For more details check the $($Options.PipelineName).log file in attachment."
    

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
    if ($response)
    {
		Out-File -FilePath $Options.OutputLogFile -InputObject $response -Append
    }
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
    if($Status -ne "start")
    {
        #Play beep sound  
        [System.Media.SystemSounds]::Beep.Play()   
    }
    #Write-Host($log)
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
        $error = "Skipping ApexSQL Document step due to failure in the pipeline"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }
	$project = ""
	if ($ProjectFile)
	{
		$ProjectFile = $options.ScriptDirectory + "\Projects\" + $ProjectFile
        $project = " /project:""$ProjectFile"""
	}
	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = " $AdditionalOptions"
	}

    #Output files names
    $sourceSwitches = ""
    $sourceSnapShot = ""
    $dbName = ""
    if ($Database.ConnectionName -ne $null)
    {
        $dbName = $Database.ConnectionName
    }
    else
    {
        $dbName = "Database"
    }
    if (!$Differential)
    {
        $reportName = "Document_$($dbName)_Documentation.$($PsCmdlet.ParameterSetName)"
        if ($Database -eq $null)
        {
            $sourceSwitches = "/dbsnp:$($Options.OutputLocation)\Db_SnapShot.axsnp" 
        }
        else
        {
            $sourceSwitches = "$($Database.AsParameters("doc"))" 
        }
    }
    else
    {
        $reportName = "Document_Differential_Documentation.$($PsCmdlet.ParameterSetName)"
        $sourceSwitches  = "/dbsnp:$($Options.OutputLocation)\Db_SnapShot_Diff.axdsn"
    }

    #Full tool parameters $($Database.AsParameters("doc"))
	$toolParameters = " /ot:$($PsCmdlet.ParameterSetName) /od:""$($Options.OutputLocation)""" +
	" /on:$reportName$project$additional $sourceSwitches   /v /f"
	$params = @{
		ToolName = "Doc"
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

    #Store output files
    $outputs = "$($Options.OutputLocation)\$($reportName)"
    $global:ResultSet.Add($global:ResultSet.Count, @("Document", (&{ if ($Options.Result-ne $null) {"$($Options.Result)"} Else {""}} ), (&{ if ($outputs -ne $null) {"$($outputs)"} Else {""}}), (&{ if ($Options.ErrorCodes -ne $null) {"$($Options.ErrorCodes)"} Else {""}} )))
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
        [Parameter(Mandatory = $true)]
        [ApexSqlConnection] $Target,
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
		[switch] $NoSummary,
        [Parameter(Mandatory = $false)]
		[switch] $NoWarnings,
        [Parameter(Mandatory = $false)]
		[switch] $SourceFromPipeline

	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tSchemaSync`r`n"
        $error = "Skipping ApexSQL Schemasync step due to failure in the pipeline"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }
	$project = ""
	if ($ProjectFile)
	{
        $ProjectFile = $options.ScriptDirectory + "\Projects\" + $ProjectFile
        $project = " /project:""$ProjectFile"""
	}
	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = " $AdditionalOptions"
	}

    #Output files names
    $schemaSyncScript  = "$($Options.OutputLocation)\SchemaSync_$($Source.ConnectionName)_$($Target.ConnectionName)_SyncScript.sql"
    $schemaSyncReport  = "$($Options.OutputLocation)\SchemaSync_$($Source.ConnectionName)_$($Target.ConnectionName)_DiffReport.html"
    $schemaSyncWarnings = "$($Options.OutputLocation)\SchemaSync_$($Source.ConnectionName)_$($Target.ConnectionName)_SyncWarnings.log"
    $schemaSyncSummary = "$($Options.OutputLocation)\SchemaSync_$($Source.ConnectionName)_$($Target.ConnectionName)_DiffSummary.log"

    #Check if source is .nupkg
    $sourceParameters = ""
    if (!$SourceFromPipeline)
    {
        if ($Source.NugetID)
        {
            if ($Source.Latest -eq $true)
                    {
            ExtractNupkg -OutputLocation $Options.OutputLocation -NugetID $Source.NugetID -Source $Source.Source
        }
            else
                    {
            ExtractNupkg -OutputLocation $Options.OutputLocation -NugetID $Source.NugetID -Version $Source.Version -Source $Source.Source
        }
        

            $dir = Get-ChildItem $Options.OutputLocation | ?{ $_.PSIsContainer } | sort LastWriteTime | select -last 1 | select -ExpandProperty FullName

            #Clear all files and folders except DbScriptFolder (which should be used as source)
            if($dir -ne $null)
            {
                ClearExtractedContents -path $dir
            }

            $SFPath = Get-ChildItem $dir | ?{ $_.PSIsContainer } | ?{ $_.Name -like "*DbScriptFolder*" } | select -ExpandProperty FullName | Select -Last 1 
            $sourceParameters = " /sf1:""$($SFPath)"" "
            $global:nugetDbScriptFolderSource = $sourceParameters
        }
        else
        {
            $sourceParameters = "$($Source.AsParameters("diff1"))"
        }
    }
    else
    {
        $sourceParameters = " /sf1:""$($Options.OutputLocation)\DbScriptFolder"" "
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
    $report = ""
    if (!$NoReport)
    {
        $report = " /ot:html /on:""$schemaSyncReport"""
    }
    $script = ""
    if (!$NoScript)
    {
        $script = " /ot2:sql /on2:""$schemaSyncScript"""
    }	
    $warnings = ""
    if (!$NoWarnings)
    {
        $warnings = " /wao:""$schemaSyncWarnings"""
    }
    $summary = ""
    if (!$NoSummary)
    {
        $summary = " /cso:""$schemaSyncSummary"" "
    }
    #endregion

    #Full tool parameters
    $toolParameters = "$($sourceParameters) $($Target.AsParameters("diff2")) $report $script $warnings $summary $project$additional /dsn:""$($Options.OutputLocation)\Db_SnapShot_Diff.axdsn"" /v /f"
	$params = @{
		ToolName = "Diff"
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

    #Store output files
    $outputs = ""
    if (!$NoScript)
    {
        $outputs += "$($schemaSyncScript)`r`n"
    }
    if (!$NoReport)
    {
        $TABS = &{if (!$NoScript) {"`t`t`t`t"} Else {""}}
        $outputs += "$($TABS)$($schemaSyncReport)`r`n"
    }
    if (!$NoSummary)
    {
        $TABS = &{if ($NoReport -and $NoScript) {""} Else {"`t`t`t`t"}}
        $outputs += "$($TABS)$($schemaSyncSummary)"
    }
    if (!$NoWarnings)
    {
        $TABS = &{if ($NoReport -and $NoScript -and $NoSummary) {""} Else {"`t`t`t`t"}}
        $outputs += "$($TABS)$($schemaSyncWarnings)"
    }
    $global:ResultSet.Add($global:ResultSet.Count, @("SchemaSync", (&{ if ($Options.Result-ne $null) {"$($Options.Result)"} Else {""}} ), (&{ if ($outputs -ne $null) {"$($outputs)"} Else {""}}), (&{ if ($Options.ErrorCodes -ne $null) {"$($Options.ErrorCodes)"} Else {""}} )))
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
        [Parameter(Mandatory = $true)]
        [ApexSqlConnection] $Target,
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
		[switch] $NoSummary,
        [Parameter(Mandatory = $false)]
		[switch] $NoWarnings,
        [Parameter(Mandatory = $false)]
		[switch] $SourceFromPipeline
	)
    if ($Options.Result -eq "Failure")
    {
        $global:SkippingList += "`tDataSync`r`n"
        $error = "Skipping ApexSQL DataSync step due to failure in the pipeline"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append
        if ($PSCmdlet.MyInvocation.ExpectingInput)
        {
            return $Options
        }
        else
        {
            return
        }
    }
	$project = ""
	if ($ProjectFile)
	{
        $ProjectFile = $options.ScriptDirectory + "\Projects\" + $ProjectFile
        $project = " /project:""$ProjectFile"""
	}
	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = " $AdditionalOptions"
	}

    #Output files names
    $dataSyncScript  = "$($Options.OutputLocation)\DataSync_$($Source.ConnectionName)_$($Target.ConnectionName)_SyncScript.sql"
    $dataSyncReport  = "$($Options.OutputLocation)\DataSync_$($Source.ConnectionName)_$($Target.ConnectionName)_DiffReport.html"
    $dataSyncWarnings  = "$($Options.OutputLocation)\DataSync_$($Source.ConnectionName)_$($Target.ConnectionName)_SyncWarnings.log"
    $dataSyncSummary  = "$($Options.OutputLocation)\DataSync_$($Source.ConnectionName)_$($Target.ConnectionName)_DiffSummary.log"

    $sourceParameters = ""
    if (!$SourceFromPipeline)
    {
        #Check if .nupkg sources is already configured   
        if ($global:nugetDbScriptFolderSource -ne $null)
        {
            $sourceParameters = $global:nugetDbScriptFolderSource
        }
        else
        {
            #Check if source is .nupkg
            if ($Source.NugetID)
            {
                ExtractNupkg -OutputLocation $Options.OutputLocation -NugetID $Source.NugetID -Version $Source.Version -Source $Source.Source
                $dir = Get-ChildItem $Options.OutputLocation | ?{ $_.PSIsContainer } | sort LastWriteTime | select -last 1 | select -ExpandProperty FullName

                #Clear all files and folders except DbScriptFolder (which should be used as source)
                if($dir -ne $null)
                {
                    ClearExtractedContents -path $dir
                }
                $SFPath = Get-ChildItem $dir | ?{ $_.PSIsContainer } | ?{ $_.Name -like "*DbScriptFolder*" } | select -ExpandProperty FullName | Select -Last 1 
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
        $sourceParameters = " /sf1:""$($Options.OutputLocation)\DbScriptFolder"" "
    }

    #Define outputs for tool parameters
    #region tool parameters outputs
    $report = ""
    if (!$NoReport)
    {
        $report = " /ot:html /on:""$dataSyncReport"""
    }
    $script = ""
    if (!$NoScript)
    {
        $script = " /ot2:sql /on2:""$dataSyncScript"""
    }	
    $warnings = ""
    if (!$NoWarnings)
    {
        $warnings = " /wao:""$dataSyncWarnings"""
    }
    $summary = ""
    if (!$NoSummary)
    {
        $summary = " /cso:""$dataSyncSummary"" "
    }
    #endregion

    #Full tool parameters
    $toolParameters = "$($sourceParameters) $($Target.AsParameters("diff2")) $report $script $warnings $summary $project$additional /v /f" 
	$params = @{
		ToolName = "Data Diff"
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

    #Store output files
    $outputs = ""
    if (!$NoScript)
    {
        $outputs += "$($dataSyncScript)`r`n"
    }
    if (!$NoReport)
    {
        $TABS = &{if (!$NoScript) {"`t`t`t`t"} Else {""}}
        $outputs += "$($TABS)$($dataSyncReport)`r`n"
    }
    if (!$NoSummary)
    {
        $TABS = &{if ($NoReport -and $NoScript) {""} Else {"`t`t`t`t"}}
        $outputs += "$($TABS)$($dataSyncSummary)"
    }
    $global:ResultSet.Add($global:ResultSet.Count, @("DataSync", (&{ if ($Options.Result-ne $null) {"$($Options.Result)"} Else {""}} ), (&{ if ($outputs -ne $null) {"$($outputs)"} Else {""}}), (&{ if ($Options.ErrorCodes -ne $null) {"$($Options.ErrorCodes)"} Else {""}} )))
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
        $error = "Skipping ApexSQL Deploy step due to failure in the pipeline"
        Write-Warning -Message $error
        Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append -Confirm:$false
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
            if ($Source.Version -ne $null)
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
            $lookAtDir = Get-ChildItem $Options.OutputLocation | ?{ $_.PSIsContainer } | sort LastWriteTime | select -last 1 | select -ExpandProperty FullName
        }
          

        $lookAtDir = Get-ChildItem -Path $Options.OutputLocation
        $schemaScripts = $lookAtDir | Where-Object -FilterScript {$_.Name -like "SchemaSync_*_SyncScript.sql"}
        $dataScripts   = $lookAtDir | Where-Object -FilterScript {$_.Name -like "DataSync_*_SyncScript.sql"}
        $consolidatedScript   = $lookAtDir | Where-Object -FilterScript {$_.Name -like "*Consolidated_script.sql"}
        $schemaOK = ($DeployType -eq "Schema") -and ($schemaScripts.Count -eq 1) -and $consolidatedScript.Count -eq 0
        $dataOK   = ($DeployType -eq "Data") -and ($dataScripts.Count -eq 1) -and $consolidatedScript.Count -eq 0
        $bothOK   = ($DeployType -eq "Both") -and ($schemaScripts.Count -eq 1 -or $dataScripts.Count -eq 1 -or $consolidatedScript.Count -eq 1 )

        if (($schemaOK -eq $false -and $dataOK -eq $false) -and $bothOK -eq $false)
        {
            $error = "There are no schema and data differences.`r`n" +
            "`tProcess terminated."
            Write-Warning -Message $error
            Out-File -FilePath $Options.OutputLogFile -InputObject $error -Append 
            $Options.ErrorCodes += 102
            $Options.FailedSteps += @("ApexSQL Deploy")
            $Options.Result = "Failure"
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

            if (($schemaOK -or $bothOK) -and $schemaScripts -ne $null)
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
            if (($dataOK -or $bothOK)  -and $dataScripts -ne $null)
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

        #Remove extracted package directory (we don't need it any more) 
        Remove-Item -Recurse -Force $extractedPackDir
    }
    catch
    {
        Out-File -FilePath $Options.OutputLogFile -InputObject $_.Message -Append
    }
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }

    #Write step result
    if ($Options.Result -eq "Success")
    {
        $stepName = "Deploying"
        $msg = "$stepName step passed."
        Write-Host $msg
        Out-File -FilePath $Options.OutputLogFile -InputObject "`r`n##### $($msg) #####`r`n" -Append
    }

    #Store output files
    $outputs = ""
    $global:ResultSet.Add($global:ResultSet.Count, @("Deploy", (&{ if ($Options.Result-ne $null) {"$($Options.Result)"} Else {""}} ), (&{ if ($outputs -ne $null) {"$($outputs)"} Else {""}}), (&{ if ($Options.ErrorCodes -ne $null) {"$($Options.ErrorCodes)"} Else {""}} )))
}
