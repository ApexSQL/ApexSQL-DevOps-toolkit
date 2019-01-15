<#
Instead of using plain text as an argument for $global:apiKey variable and -Password switch, 
use the $global:apiKeyFile variable and -PasswordFile switch 
and provide, as anargument, the file name where the ApiKey/password is stored.

Examples:
$global:apiKeyFile = "ApiKey_file", 
New-ApexSqlDatabaseConnection ... -PasswordFile "DBPassword" ...,
New-ApexSQLNotificationSettings ... -PasswordFile "GMailPassword" ...

To be able to provide the ApiKey and password files to $global:apiKeyFile variable and -PasswordFile switch, 
save them beforehand to files using:

Read-Host -AsSecureString |ConvertFrom-SecureString |Out-File path_to_the_script\Passwords\ApiKey_file.txt
Read-Host -AsSecureString |ConvertFrom-SecureString |Out-File path_to_the_script\Passwords\DBPassword.txt
Read-Host -AsSecureString |ConvertFrom-SecureString |Out-File path_to_the_script\Passwords\GMailPassword.txt
#>

#region Initial settings

Initialize-Globals -CurrentDirectory "$(Split-Path -parent $PSCommandPath)"
#Nuget package settings
$global:nugetId = "packageID"
$global:nugetAuthors = "ApexSQL LLC"
$global:nugetOwners = "ApexSQL LLC"
$global:pushSource = "https://some.nuget.feed.url.com"
$global:apiKeyFile = "ApiKey_file"
$global:nugetExePath = "C:\nuget.exe"

#Global options (pipeline name, output folder location and notification settings)
$options = New-ApexSqlOptions -PipelineName "CD_Pipeline"

#Email server settings used for notifications
$notificationSettings = New-ApexSQLNotificationSettings -Options $options -EmailAddress "user@example.com" -PasswordFile "PasswordFileName" -SmtpServer "some.smtp.server.com" -Port 587 -UseSSL 

#endregion


#region Datasources definition

#Define data source: NuGet pacakge
$stageDB = New-ApexSQLSource -ConnectionName "stageDB" -Source_Type nuget -Source "https://some.nuget.feed.url.com" -NugetID "packageID" -Version "packageVersion"

#Define data source: database (production)
$productionDB = New-ApexSqlDatabaseConnection -ConnectionName "productionDB" -Server "serverName" -Database "databaseName" -WindowsAuthentication

#endregion


#region CD pipeline steps in order of execution

#Notification step
#Invoke-ApexSqlNotifyStep -Options $options -DistributionList "user@example.com" -Status started

#SchemaSync step
Invoke-ApexSqlSchemaSyncStep -Options $options -Source $stageDB -Target $productionDB -Verbose | Out-Null

#DataSync step
Invoke-ApexSqlDataSyncStep -Options $options -Source $stageDB -Target $productionDB -Verbose | Out-Null

#Deploy step
Invoke-ApexSqlDeployStep -Options $options -DeployType Both -Database $productionDB -Verbose | Out-Null

#Notification step
Invoke-ApexSqlNotifyStep -Options $options -DistributionList "user@example.com" -Status completed -Verbose

#endregion





