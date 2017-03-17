#region Initial settings

#Email server settings used for notifications
$notificationSettings = New-ApexSQLNotificationSettings -EmailAddress "example@email.com" -Password "mail_password" -SmtpServer "smtp.email.com" -Port 587 -UseSSL

#Global options (pipeline name, output folder locatioin and notification settings)
$options = New-ApexSqlOptions -PipelineName "CD_Pipeline" -OutputLocation "C:\CICD" -NotificationSettings $notificationSettings

#endregion



#region Datasources definition

#Define data source: database SQL script file (result of CI pipeline)
$buildFile = New-ApexSqlFileConnection -ConnectionName "buildFile" -FilePath "C:\CICD\CI_Pipeline\drop_folder\tfs_qaDb_Build_script.sql"

#Define data source: new database (staging)
$stageDB = New-ApexSqlDatabaseConnection -ConnectionName "stageDB" -Server "ServerName" -Database "stageDB$($options.Timestamp)" -WindowsAuthentication

#Define data source: database (production)
$productionDB = New-ApexSqlDatabaseConnection -ConnectionName "productionDB" -Server "ProductionServer" -Database "productionDB" -UserName "admin" -Password "password"

#endregion



#region Execution of steps

#Send notification on pipeline start
Invoke-ApexSqlNotifyStep -Options $options -DistributionList "qa@example.com","dev@example.com" -Status started

#Build staging database from SQL script file
Invoke-ApexSqlBuildStep -Options $options -Source $buildFile -Database $stageDB -StopOnFail $false

#Create schema sync script between staging and production database
Invoke-ApexSqlSchemaSyncStep -Options $options -Source $stageDB -Database $productionDB

#Create data sync script between staging and production database
Invoke-ApexSqlDataSyncStep -Options $options -Source $stageDB -Database $productionDB

#Create documentation of the staging database (pdf)
Invoke-ApexSqlDocumentStep -Options $options -Database $stageDB -AsPdf

#Package all created files into "Package.zip"
Invoke-ApexSqlPackageStep -Options $options -IncludeReleaseNotes Both -IncludeReports -IncludeDocumentation

#Deploy the package to the production database
Invoke-ApexSqlDeployStep -Options $options -DeployType Both -Latest -Databases $productionDB

#Send notification with results on pipeline end
Invoke-ApexSqlNotifyStep -Options $options -DistributionList "qa@example.com","dev@example.com" -Status completed

#endregion