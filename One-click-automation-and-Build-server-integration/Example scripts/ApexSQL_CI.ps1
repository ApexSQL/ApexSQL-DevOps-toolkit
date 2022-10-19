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
$global:nugetId = "packageID"
$global:nugetAuthors = "Quest Software Inc"
$global:nugetOwners = "Quest Software Inc"
$global:pushSource = "https://some.nuget.feed.url.com"
$global:apiKeyFile = "ApiKey_file"
$global:nugetExePath = "C:\nuget.exe"

#Global options (pipeline name, output folder location and notification settings)
$options = New-ApexSqlOptions -PipelineName "CI_Pipeline"

#Email server settings used for notifications
$notificationSettings = New-ApexSQLNotificationSettings -Options $options -EmailAddress "user@example.com" -PasswordFile "PasswordFileName" -SmtpServer "some.smtp.server.com" -Port 587 -UseSSL 

#endregion


#region Data source definitions

#Define data source
$dsSC = New-ApexSQLSource -ConnectionName "git_source" -Source_Type "git"-Repository "https://github.com/user/someRepository.git" -Project "$/projectName" -U "user@example.com" -PasswordFile "passwordFileName"

#Define target: new database (testing)
$dsQA = New-ApexSqlDatabaseConnection -ConnectionName "qaDB_dest" -Server "serverName" -Database "databaseName" -WindowsAuthentication

#endregion


#region CI pipeline steps in order of execution

#Notification step
#Invoke-ApexSqlNotifyStep -Options $options -DistributionList "user@example.com" -Status started

#Compare step
#Invoke-ApexSQLCompareStep -Options $options -Source $dsSC -Target $dsQA -Verbose

#Build step
Invoke-ApexSqlBuildStep -Options $options -Source $dsSC -Database $dsQA -Verbose | Out-Null

#Populate step
Invoke-ApexSqlPopulateStep -Options $options -Database $dsQA -RowCount 100 -Verbose | Out-Null

#Audit step
#Invoke-ApexSqlAuditStep -Options $options -Database $dsQA -Verbose | Out-Null

#Review step
Invoke-ApexSqlReviewStep -Options $options -Database $dsQA -ProjectFile "Review_RuleBase.axrb" -Passed -Failed -Errors -Verbose | Out-Null

#Test step
Invoke-ApexSqlTestStep -Options $options -Database $dsQA -InstallSqlCop -Verbose | Out-Null

#Document step
Invoke-ApexSqlDocumentStep -Options $options -Database $dsQA -AsPdf -Verbose | Out-Null

#Package step
Invoke-ApexSqlPackageStep -Options $options -Database $dsQA -nugetVersion "1.0.5" -nugetReleaseNotes "Release notes text here" -Publish -Verbose | Out-Null

#Notification step
Invoke-ApexSqlNotifyStep -Options $options -DistributionList "user@example.com" -Status completed -Verbose

#endregion

 
