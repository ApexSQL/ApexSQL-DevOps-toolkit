<#
Instead of using plain text as an argument for $global:apiKey variable and -Password switch, 
use the $global:apiKeyFile variable and -PasswordFile switch 
and provide, as anargument, the file name where the ApiKey/password is stored.

Examples:
$global:apiKeyFile = "ApiKey_file", 
New-ApexSQLSource ... -PasswordFile "SourcePassword" ...,
New-ApexSqlDatabaseConnection ... -PasswordFile "DBPassword" ...,
New-ApexSQLNotificationSettings ... -PasswordFile "GMailPassword" ...

To be able to provide the ApiKey and password files to $global:apiKeyFile variable and -PasswordFile switch, 
save them beforehand to files using:

Read-Host -AsSecureString |ConvertFrom-SecureString |Out-File path_to_the_script\Passwords\ApiKey_file.txt
Read-Host -AsSecureString |ConvertFrom-SecureString |Out-File path_to_the_script\Passwords\SourcePassword.txt
Read-Host -AsSecureString |ConvertFrom-SecureString |Out-File path_to_the_script\Passwords\DBPassword.txt
Read-Host -AsSecureString |ConvertFrom-SecureString |Out-File path_to_the_script\Passwords\GMailPassword.txt
#>


#region Initial settings
Initialize-Globals -CurrentDirectory "$(Split-Path -parent $PSCommandPath)"

#Nuget package settings
$global:nugetId = "package"
$global:nugetAuthors = "ApexSQL LLC"
$global:nugetOwners = "ApexSQL LLC"
$global:pushSource = "https://devopsnenad.pkgs.visualstudio.com/_packaging/test.apexsql/nuget/v3/index.json"
$global:apiKeyFile = "ApiKey_file"
$global:nugetExePath = "C:\Program Files\ApexSQL\ApexSQL CICD toolkit\Modules\ApexSQL_cicd\nuget.exe"

#Global options (pipeline name, output folder location and notification settings)
$options = New-ApexSqlOptions -PipelineName "CI_Pipeline"

#Email server settings used for notifications
$notificationSettings = New-ApexSQLNotificationSettings -EmailAddress "example@gmail.com" -Password "GMailPassword" -SmtpServer "smtp.gmail.com" -Port 587 -UseSSL

#endregion


#region Data source definitions

#Define data source
$dsSC = New-ApexSQLSource -ConnectionName "tfs_source" -Source_Type "tfs" -Server "https://devopsnenad.visualstudio.com/" -Project "$/Database" -UserName "devopsnenad" -PasswordFile "SourcePassword"

#Define target: new database (testing)
$dsQA = New-ApexSqlDatabaseConnection -ConnectionName "qaDB_dest" -Server "localhost" -Database "test_DB" -UserName "sa" -PasswordFile "DBPassword"

#endregion


#region CI pipeline steps in order of execution

#Notification step
#Invoke-ApexSqlNotifyStep -Options $options -DistributionList "example@gmail.com" -Status started

#Build step
Invoke-ApexSqlBuildStep -Options $options -Source $dsSC -Database $dsQA | Out-Null

#Populate step
Invoke-ApexSqlPopulateStep -Options $options -Database $dsQA -RowCount 100 | Out-Null

#Audit step
Invoke-ApexSqlAuditStep -Options $options -Database $dsQA | Out-Null

#Review step
#Invoke-ApexSqlReviewStep -Options $options -Database $dsQA -ProjectFile "Review_RuleBase.axrb" -Passed -Failed -Errors | Out-Null

#Test step
Invoke-ApexSqlTestStep -Options $options -Database $dsQA -InstallSqlCop | Out-Null

#Package step
Invoke-ApexSqlPackageStep -Options $options -nugetVersion "1.1.2" -nugetReleaseNotes "Release_notes_here" -Publish | Out-Null

#Notification step
Invoke-ApexSqlNotifyStep -Options $options -DistributionList "example@gmail.com" -Status completed

#endregion


