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
$global:nugetId = "ApexSQL_CD"
$global:nugetAuthors = "ApexSQL LLC"
$global:nugetOwners = "ApexSQL LLC"
$global:pushSource = "cicd.apexsql"
$global:apiKeyFile = "ApiKey_file"
$global:nugetExePath = "C:\Program Files\ApexSQL\ApexSQL DevOps toolkit\Modules\ApexSQL_DevOps\nuget.exe"

#Global options (pipeline name, output folder location and notification settings)
$options = New-ApexSqlOptions -PipelineName "CD_Pipeline"

#Email server settings used for notifications
$notificationSettings = New-ApexSQLNotificationSettings -Options $options -EmailAddress "example@gmail.com" -PasswordFile "GMailPassword" -SmtpServer "smtp.gmail.com" -Port 587 -UseSSL

#endregion


#region Datasources definition

#Define data source: NuGet pacakge
$stageDB = New-ApexSQLSource -ConnectionName "stageDB" -Source_Type nuget -Source "cicd.apexsql" -NugetID "ApexSQL_CI" -Latest $true

#Define data source: database (production)
$productionDB = New-ApexSqlDatabaseConnection -ConnectionName "productionDB" -Server "production_server" -Database "database_PROD" -UserName "sa" -PasswordFile "DBPassword"

#endregion


#region CD pipeline steps in order of execution

#Notification step
#Invoke-ApexSqlNotifyStep -Options $options -DistributionList "example@gmail.com" -Status started

#SchemaSync step
Invoke-ApexSqlSchemaSyncStep -Options $options -Source $stageDB -Target $productionDB | Out-Null

#DataSync step
Invoke-ApexSqlDataSyncStep -Options $options -Source $stageDB -Target $productionDB | Out-Null

#Document step
Invoke-ApexSqlDocumentStep -Options $options -AsChm -Differential | Out-Null

#Deploy step
Invoke-ApexSqlDeployStep -Options $options -Source $stageDB -DeployType Both -Database $productionDB | Out-Null


#Notification step
Invoke-ApexSqlNotifyStep -Options $options -DistributionList "example@gmail.com" -Status completed

#endregion





