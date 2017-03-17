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
                $_username = "[:$($this.UserName)]"
                $_password = "[.$($this.Password)]"
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

        [Parameter(Mandatory = $true)]
	    [string] $Server,

        [Parameter(Mandatory = $true)]
        [string] $Database,

        [Parameter(Mandatory = $true, ParameterSetName = "winAuth")]
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
    [string] $Type
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
        $_type = "/sourcecontrol_type$($id):$($this.Type)"
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
    $connection.Type = "git"
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
    $connection.Type = "teamfoundationserver"
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
    $connection.Type = "mercurial"
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
    $connection.Type = "subversion"
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
    $connection.Type = "perforce"
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

        [Parameter(Mandatory = $true)]
        [string] $Password,

        [Parameter(Mandatory = $true)]
        [string] $SmtpServer,

        [Parameter(Mandatory = $true)]
        [int]    $Port,

        [Parameter(Mandatory = $false)]
        [switch] $UseSSL
    )
    $pass = $Password | ConvertTo-SecureString -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($EmailAddress, $pass)
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
	[ApexSqlNotificationSettings] $NotificationSettings
	[string] $OutputLogFile
    [string] $PackageFilePath

    [string[]] $BuildScripts
    [string[]] $SchemaSyncScripts
    [string[]] $DataSyncScripts
    [string[]] $AuditScripts

    [string[]] $SchemaSyncReports
    [string[]] $DataSyncReports
    [string[]] $DocumentationReports
    [string[]] $TestReports

    [string[]] $SchemaSyncSummaries
    [string[]] $DataSyncSummaries

    [string]   $Timestamp
	[string[]] $ErrorCodes
	[string[]] $FailedSteps
	[string]   $Result = "Success"
}

function New-ApexSqlOptions
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $PipelineName,

        [Parameter(Mandatory = $true)]
        [string] $OutputLocation,

        [Parameter(Mandatory = $true)]
        [ApexSqlNotificationSettings] $NotificationSettings,

        [Parameter(Mandatory = $false)]
        [switch] $NoSubfolders
    )
    $timestamp = Get-Date -Format "MM_dd_yyyy_HH-mm-ss"

    $options = New-Object -TypeName ApexSqlOptions
    $options.PipelineName = $PipelineName
    if ($NoSubfolders)
    {
        $options.OutputLocation = $OutputLocation
    }
    else
    {
        $options.OutputLocation = "$OutputLocation\$PipelineName\$timestamp"
    }
    $options.Timestamp = $timestamp
	$options.OutputLogFile = "$($options.OutputLocation)\Output.txt"
    $options.NotificationSettings = $NotificationSettings
    if (-not (Test-Path $options.OutputLocation))
    {
        New-Item -Path $OutputLocation -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path $options.OutputLocation))
    {
        New-Item -Path $options.OutputLogFile -ItemType File -Force | Out-Null
    }
    $options.PackageFilePath = "$($options.OutputLocation)\Package.zip"
    return $options
}
#endregion

#region Helpers
function Get-ApexSQLToolLocation
{
    param
    (
        [Parameter(Mandatory = $true)]
        [String] $ApplicationName
    )
    $key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ApexSQL $($ApplicationName)_is1"
    if(Test-Path "HKLM:\$Key")
    {
		$ApplicationPath = (Get-ItemProperty -Path "HKLM:\$key" -Name InstallLocation).InstallLocation
	} 
    else 
    {
		$reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
		
		$regKey= $reg.OpenSubKey("$key")
		if($regKey) 
        {
			$ApplicationPath = $regKey.GetValue("InstallLocation")  
		} 
        else 
        {
			$reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)
			$regKey= $reg.OpenSubKey("$key")
			if($regKey) 
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
		[bool] $StopOnFail
	)
	$logFile = "$OutputLocation\Output.txt"
	$toolLocation = Get-ApexSQLToolLocation $ToolName
    if (-not $toolLocation)
    {
        return $false
    }
	$info = "`r`n`r`nStarting execution of ApexSQL $ToolName `r`n"
	Out-File -FilePath $Options.OutputLogFile -InputObject $info -Append
	$output = Invoke-Expression -Command ("& `"$($toolLocation)`" $ToolParameters")
	Out-File -FilePath $Options.OutputLogFile -InputObject $output -Append
	
	if ($lastExitCode -ne 0) 
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
    return $true
}
#endregion


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
		[string] $AdditionalOptions
	)
    if ($Options.Result -eq "Failure")
    {
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
       $project = " /project:""$ProjectFile"""
    }
    $additional = ""
    if ($AdditionalOptions)
    {
       $additional = " $AdditionalOptions"
    }
    $toolParameters = "$($Database.AsParameters())$project$additional /at /v /f"
    $params = @{
        ToolName = "Trigger"
        ToolParameters = $toolParameters 
        Options = $Options
        StopOnFail = $StopOnFail
    }
    if (Start-ApexSQLTool @params)
    {
        $Options.AuditScripts += @($auditScript)
    }
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
}


function Invoke-ApexSqlBuildStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

		[Parameter(Mandatory = $true)]
        [ValidateScript({
            if (($_.GetType() -ne [ApexSqlSourceControlConnection]) -and ($_.GetType() -ne [ApexSqlFileConnection]))
            {
                Throw "Only source control or file connection can be used as a source"
            }
            return $true
        })]
		[ApexSqlConnection] $Source,

        [ValidateScript({
            if (($_.GetType() -ne [ApexSqlDatabaseConnection]) -and ($_.GetType() -ne [ApexSqlFileConnection]))
            {
                Throw "Only source control or file connection can be used as a source"
            }
            return $true
        })]
        [Parameter(Mandatory = $true)]
        [ApexSqlConnection] $Database,

		[Parameter(Mandatory = $false)]
		[bool] $DropIfExists,

		[Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true,

		[Parameter(Mandatory = $false)]
		[string] $ProjectFile,

		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions
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
	if ($ProjectFile)
	{
		$project = " /project:""$ProjectFile"""
	}
	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = " $AdditionalOptions"
	}
	$drop = ""
	if ($DropIfExists)
	{
		$drop = " /drop_if_exists"
	}
    $sourceType = "sc"
    $databaseType = "db"    
    if ($Source.GetType() -eq [ApexSqlFileConnection])
    {
        $sourceType = "sql"
        $sourceParams = "/source_name:""$($Source.FilePath)"""
    }
	else
	{
		$sourceParams = $Source.AsParameters()
	}
    if ($database.GetType() -eq [ApexSqlFileConnection])
    {
        $databaseType = "sql"
        $databaseParams = "/output_name:""$($Database.FilePath)"""
    }
	else
	{
		$databaseParams = $Database.AsParameters()
	}
    $buildScript = "$($Options.OutputLocation)\$($Source.ConnectionName)_$($Database.ConnectionName)_Build_script.sql"
    $toolParameters = "/source_type:$sourceType $sourceParams /output_type:$databaseType $DatabaseParams /script_permissions" +
	" /os:""$buildScript""$project$additional$drop /v /f"
	$params = @{
		ToolName = "Build"
		ToolParameters = $toolParameters 
		Options = $Options
		StopOnFail = $StopOnFail
	}
	if (Start-ApexSQLTool @params)
    {
        $Options.BuildScripts += @($buildScript)
    }
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
}


function Invoke-ApexSqlDocumentStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,

		[Parameter(Mandatory = $true)]
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
		[string] $AdditionalOptions
	)
    if ($Options.Result -eq "Failure")
    {
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
		$project = " /project:""$ProjectFile"""
	}
	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = " $AdditionalOptions"
	}
    $reportName = "$($Database.ConnectionName)_Document_documentation"
	$toolParameters = "$($Database.AsParameters("doc")) /of:$($PsCmdlet.ParameterSetName) /od:""$($Options.OutputLocation)""" +
	" /on:$reportName$project$additional /v /f"
	$params = @{
		ToolName = "Doc"
		ToolParameters = $toolParameters 
		Options = $Options
		StopOnFail = $StopOnFail
	}
	if (Start-ApexSQLTool @params)
    {
        $Options.DocumentationReports += @("$($Options.OutputLocation)\$reportName.$($PsCmdlet.ParameterSetName)")
    }
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
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
		[string] $AdditionalOptions
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
	$toolParameters = "$($Database.AsParameters()) /r:$($RowCount)$fillEmpty$project$additional /v /f "
	$params = @{
		ToolName = "Generate"
		ToolParameters = $toolParameters 
		Options = $Options
		StopOnFail = $StopOnFail
	}
	Start-ApexSQLTool @params | Out-Null
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
		[Parameter(Mandatory = $true)]
		[ApexSqlConnection] $Source,
        [Parameter(Mandatory = $true)]
        [ApexSqlConnection] $Database,
		[Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true,
		[Parameter(Mandatory = $false)]
		[string] $ProjectFile,
		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions
	)
    if ($Options.Result -eq "Failure")
    {
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
		$project = " /project:""$ProjectFile"""
	}
	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = " $AdditionalOptions"
	}
    $dataSyncScript  = "$($Options.OutputLocation)\$($Source.ConnectionName)_$($Database.ConnectionName)_DataSync_script.sql"
    $dataSyncReport  = "$($Options.OutputLocation)\$($Source.ConnectionName)_$($Database.ConnectionName)_DataSync_report.html"
    $dataSyncSummary  = "$($Options.OutputLocation)\$($Source.ConnectionName)_$($Database.ConnectionName)_DataSync_summary.log"
    $toolParameters = "$($Source.AsParameters("diff1")) $($Database.AsParameters("diff2"))" +
	" /ot:html /on:""$dataSyncReport""" +
	" /ot2:sql /on2:""$dataSyncScript""$project$additional " +
    " /cso:""$dataSyncSummary"" /v /f" 
	$params = @{
		ToolName = "Data Diff"
		ToolParameters = $toolParameters 
		Options = $Options
		StopOnFail = $StopOnFail
	}
	if (Start-ApexSQLTool @params)
    {
        $Options.DataSyncScripts   += @($dataSyncScript)
        $Options.DataSyncReports   += @($dataSyncReport)
        $Options.DataSyncSummaries += @($dataSyncSummary)
    }
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
		[Parameter(Mandatory = $true)]
		[ApexSqlConnection] $Source,
        [Parameter(Mandatory = $true)]
        [ApexSqlConnection] $Database,
		[Parameter(Mandatory = $false)]
		[bool] $StopOnFail = $true,
		[Parameter(Mandatory = $false)]
		[string] $ProjectFile,
		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions
	)
    if ($Options.Result -eq "Failure")
    {
        $error = "Skipping ApexSQL Schemaync step due to failure in the pipeline"
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
		$project = " /project:""$ProjectFile"""
	}
	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = " $AdditionalOptions"
	}
    $schemaSyncScript  = "$($Options.OutputLocation)\$($Source.ConnectionName)_$($Database.ConnectionName)_SchemaSync_script.sql"
    $schemaSyncReport  = "$($Options.OutputLocation)\$($Source.ConnectionName)_$($Database.ConnectionName)_SchemaSync_report.html"
    $schemaSyncSummary = "$($Options.OutputLocation)\$($Source.ConnectionName)_$($Database.ConnectionName)_SchemaSync_summary.log"

    $toolParameters = "$($Source.AsParameters("diff1")) $($Database.AsParameters("diff2"))" +
	" /ot:html /on:""$schemaSyncReport""" +
	" /ot2:sql /on2:""$schemaSyncScript""" +
    " /cso:""$schemaSyncSummary""$project$additional /v /f"
	$params = @{
		ToolName = "Diff"
		ToolParameters = $toolParameters 
		Options = $Options 
		StopOnFail = $StopOnFail
	}
	if (Start-ApexSQLTool @params)
    {
        $Options.SchemaSyncScripts   += @($schemaSyncScript)
        $Options.SchemaSyncReports   += @($schemaSyncReport)
        $Options.SchemaSyncSummaries += @($schemaSyncSummary)
    }
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
		[bool] $StopOnFail = $true,

		[Parameter(Mandatory = $false)]
		[string] $ProjectFile,

		[Parameter(Mandatory = $false)]
		[string] $AdditionalOptions
	)
    if ($Options.Result -eq "Failure")
    {
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
	$project = ""
	if ($ProjectFile)
	{
		$project = " /project:""$ProjectFile"""
	}
	$additional = ""
	if ($AdditionalOptions)
	{
		$additional = " $AdditionalOptions"
	}
    $testReport = "$($Options.OutputLocation)\$($Database.ConnectionName)_Test_TestResults.xml"
	$toolParameters = "$($Database.AsParameters()) /install_tsqlt" +
    " /or:""$testReport""$project$additional /v /f"
	$params = @{
		ToolName = "Unit Test"
		ToolParameters = $toolParameters 
		Options = $Options
		StopOnFail = $StopOnFail
	}
	if (Start-ApexSQLTool @params)
    {
        $Options.TestReports = @($testReport)
    }
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

        [Parameter(Mandatory = $true)]
        [ValidateSet("Schema", "Data", "Both")]
        [string] $DeployType,

        [Parameter(Mandatory = $true, ParameterSetName = "Latest")]
        [switch] $Latest,
        
        [Parameter(Mandatory = $true, ParameterSetName = "Specific")]
        [switch] $Specific,

        [Parameter(Mandatory = $true, ParameterSetName = "Specific")]
        [string] $PackageFilePath,
        
        [Parameter(Mandatory = $true)]
        [ApexSqlDatabaseConnection[]] $Databases
    )
    if ($Options.Result -eq "Failure")
    {
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
    if ($Latest)
    {
        $PackageFilePath = $Options.PackageFilePath
    }
    try
    {
        if (-not (Test-Path $PackageFilePath))
        {
            throw "Package file does not exist on the the given path: $PackageFilePath"
        }
        $tempDir = "$($env:Temp)\$([System.Guid]::NewGuid().ToString())"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        Expand-Archive -Path $PackageFilePath -DestinationPath $tempDir -Force
        $zipFiles = Get-ChildItem -Path $tempDir
        $schemaScripts = $zipFiles | Where-Object -FilterScript {$_.Name -like "*_SchemaSync_script.sql"}
        $dataScripts   = $zipFiles | Where-Object -FilterScript {$_.Name -like "*_DataSync_script.sql"}
        $noSchema = ($DeployType -ne "Data") -and ($schemaScripts.Count -ne 1)
        $noData   = ($DeployType -ne "Schema") -and ($dataScripts.Count -ne 1)

        if ($noSchema -or $noData)
        {
            throw "The number of schema and/or data sync scripts in the given package file is incorrect`r`n"+
                  "The package should contain exactly one schema and/or data sync script"
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

            if (-not $noSchema)
            {
                $schema = $schemaScripts[0].FullName
                $result = Invoke-Expression -Command "$sqlcmdProps ""$schema"""
                Out-File -FilePath $Options.OutputLogFile -InputObject $result -Append
                if ($LastExitCode -ne 0)
                {
                    $Options.ErrorCodes += @($LastExitCode)
                    $Options.FailedSteps += @("ApexSQL Deploy")
                    $Options.Result = "Failed"
                    throw "Schema synchronization failed"
                }
            }
            if (-not $noData)
            {
                $data = $dataScripts[0].FullName
                $result = Invoke-Expression -Command "$sqlcmdProps ""$data"""
                Out-File -FilePath $Options.OutputLogFile -InputObject $result -Append
                if ($LastExitCode -ne 0)
                {
                    $Options.ErrorCodes += @($LastExitCode)
                    $Options.FailedSteps += @("ApexSQL Deploy")
                    $Options.Result = "Failed"
                    throw "Data synchronization failed"
                }
            }
            Remove-Item -Path $tempDir -Force -Recurse
        }
    }
    catch
    {
        Out-File -FilePath $Options.OutputLogFile -InputObject $_.Message -Append
        Remove-Item -Path $tempDir -Force -Recurse
    }
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
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
    if (-not $Body)
    {
        $Body = "%PipelineName% %Status% at %DateTime% "
        if ($Status -ne "started")
        {
           $Body += "with result: %Result%`r`n`r`nFailed steps:`r`n"
        }
    }
    if(-not $Subject)
    {
        $Subject = "%PipelineName% pipeline notification: %Status% at %DateTime%" 
        if ($Status -ne "started")
        {
           $Subject += " with result: %Result%"
        }
    }
    if(-not $FailureEnumeration)
    {
        $FailureEnumeration = "%FailedSteps% with error code: %ErrorCodes%`r`n"
    }
    $Body = $Body -replace "%PipelineName%", $Options.PipelineName `
        -replace "%Status%", $Status `
        -replace "%DateTime%", (Get-Date) `
        -replace "%Result%", $Options.Result `
        -replace "%ErrorNum%", $Options.LastExitCode
    $Subject = $Subject -replace "%PipelineName%", $Options.PipelineName `
        -replace "%Status%", $Status `
        -replace "%DateTime%", (Get-Date) `
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
    if ($Status -ne "started")
    {
        $fullBody += $failures
    }
    $mailprops=@{
        Subject = $Subject
        Body = $fullBody
        To = $DistributionList
        From = $Options.NotificationSettings.Credential.UserName
        SmtpServer = $Options.NotificationSettings.SmtpServer
        UseSsl = $Options.NotificationSettings.UseSSL
        Port = $Options.NotificationSettings.Port
        Credential = $Options.NotificationSettings.Credential
    }
    for ($i = 0; $i -lt $RetryCount; $i++)
    {
        try
        {
            Send-MailMessage @mailprops -ErrorAction:Stop
            $responce = $null
            break
        }
        catch
        {
            $responce = "`r`nNotification step failed after $RetryCount retries with message:`r`n$($_.Exception)"
        }
    }
    if ($responce)
    {
		Out-File -FilePath $Options.OutputLogFile -InputObject $responce -Append
    }
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
}

function Invoke-ApexSqlPackageStep
{
    [CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ApexSqlOptions] $Options,
		[ValidateSet("Schema","Data","Both")]
		[string] $IncludeReleaseNotes,
        [switch] $IncludeReports,
        [switch] $IncludeDocumentation,
		[switch] $Consolidate
	)
    if ($Options.Result -eq "Failure")
    {
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
    $destination = "$($Options.OutputLocation)\Package"
    if(-not (Test-Path -Path $destination))
	{
        New-Item -Path $destination -ItemType Directory -Force | Out-Null
	}
	$files = $Options.SchemaSyncScripts + $Options.DataSyncScripts
    if($Consolidate)
	{
        $consolidatedScript = "$destination\Consolidated_script.sql"
        if ($Options.SchemaSyncScript -and (Test-Path -Path $Options.SchemaSyncScript))
        {
        	$content += Get-Content -Path $Options.SchemaSyncScript
	    }
        if ($Options.DataSyncScript-and (Test-Path -Path $Options.DataSyncScript))
        {
        	$content += Get-Content -Path $Options.DataSyncScript
	    }
        if ($content)
        {
            $content > $consolidatedScript
        }
        $files = @($consolidatedScript)
	}

	if ($IncludeReleaseNotes -eq "Both")
	{
		$summaries = $Options.SchemaSyncSummaries + $Options.DataSyncSummaries
	}
	elseif($IncludeReleaseNotes -eq "Schema")
	{
		$summaries = @($Options.SchemaSyncSummaries)
	}
	elseif($IncludeReleaseNotes -eq "Data")
	{
		$summaries = @($Options.DataSyncSummaries)
	}
	$summaries | ForEach-Object {
		if ($_ -and (Test-Path -Path $_))
		{
			$content += Get-Content $_
		}
	}
	if ($content)
	{
	    $content > "$destination\ReleaseNotes.txt"
        $files += @("$destination\ReleaseNotes.txt")
	}

    if ($IncludeDocumentation)
    {
        $files+= $Options.DocumentationReports
    }
    if ($IncludeReports)
    {
        $files+= $Options.SchemaSyncReports
        $files+= $Options.DataSyncReports
        $files+= $Options.TestReports
    }
    $files += $Options.BuildScripts

    Compress-Archive -Path $files -DestinationPath $Options.PackageFilePath -CompressionLevel Optimal -Force
    Remove-Item -Path $destination -Force -Recurse
    if ($PSCmdlet.MyInvocation.ExpectingInput)
    {
        return $Options
    }
}
