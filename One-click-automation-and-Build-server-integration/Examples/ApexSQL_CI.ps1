#region Initial settings

#Email server settings used for notifications
$notificationSettings = New-ApexSQLNotificationSettings -EmailAddress "example@email.com" -Password "mail_password" -SmtpServer "smtp.email.com" -Port 587 -UseSSL

#Global options (pipeline name, output folder locatioin and notification settings)
$options = New-ApexSqlOptions -PipelineName "CI_Pipeline" -OutputLocation "C:\CICD" -NotificationSettings $notificationSettings

#endregion



#region Data source definitions

#Define data source: Team Foundation Server repository created by ApexSQL Source Control
$scRepo = New-ApexSqlTfsSourceControlConnection -ConnectionName "tfs" -Server "https://tfs.example.com:12345/tfs/" -Project "$/ProjectPath" -UserName "user" -Password "password"

#Define data source: new database (testing)
$qaDB = New-ApexSqlDatabaseConnection -ConnectionName "qaDB"  -Server "ServerName" -Database "qaDB$($options.Timestamp)" -WindowsAuthentication

#endregion



#region CI pipeline steps in order of execution

#Send notification on pipeline start
Invoke-ApexSqlNotifyStep -Options $options -DistributionList "qa@example.com","dev@example.com" -Status started

#Build testing database from Team Foundation Server repository
Invoke-ApexSqlBuildStep -Options $options -Source $scRepo -Database $qaDB -StopOnFail $false

#Fill empty tables only in the database with 1,000 rows of synthetic data
Invoke-ApexSqlPopulateStep -Options $options -Database $qaDB -RowCount 1000 -FillOnlyEmptyTables

#Create triggers to audit sensitive data
Invoke-ApexSqlAuditStep -Options $options -Database $qaDB

#Run intalled unit tests
Invoke-ApexSqlTestStep -Options $options -Database $qaDB | Out-Null

#Send notification with results on pipeline end
Invoke-ApexSqlNotifyStep -Options $options -DistributionList "qa@example.com","dev@example.com" -Status completed

#endregion
