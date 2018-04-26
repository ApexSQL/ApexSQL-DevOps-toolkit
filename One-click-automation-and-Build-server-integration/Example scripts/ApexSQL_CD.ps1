#region Initial settings

Initialize-Globals -CurrentDirectory "$(Split-Path -parent $PSCommandPath)"
#Nuget package settings
$global:nugetId = "ApexSQL_CD"
$global:nugetAuthors = "ApexSQL LLC"
$global:nugetOwners = "ApexSQL LLC"
$global:pushSource = "cicd.apexsql"
$global:apiKey = "*******"
$global:userName = "user@email.com"
$global:password = "*******"
$global:nugetExePath = "C:\Program Files\ApexSQL\ApexSQL CICD toolkit\Modules\ApexSQL_cicd\nuget.exe"

#Email server settings used for notifications
$notificationSettings = New-ApexSQLNotificationSettings -EmailAddress "*******@email.com" -Password "*******" -SmtpServer "smtp.gmail.com" -Port 587 -UseSSL

#Global options (pipeline name, output folder location and notification settings)
$options = New-ApexSqlOptions -PipelineName "CD_Pipeline" -NotificationSettings $notificationSettings

#endregion


#region Datasources definition

#Define data source: NuGet pacakge
$stageDB = New-ApexSQLSource -ConnectionName "stageDB" -Source_Type nuget -Source "cicd.apexsql" -NugetID "ApexSQL_CI" -Latest $true

#Define data source: database (production)
$productionDB = New-ApexSqlDatabaseConnection -ConnectionName "productionDB" -Server "server" -Database "database_PROD" -WindowsAuthentication

#endregion


#region CD pipeline steps in order of execution

#Notification step
#Invoke-ApexSqlNotifyStep -Options $options -DistributionList "*******@gmail.com" -Status started

#SchemaSync step
Invoke-ApexSqlSchemaSyncStep -Options $options -Source $stageDB -Target $productionDB -No | Out-Null

#DataSync step
Invoke-ApexSqlDataSyncStep -Options $options -Source $stageDB -Target $productionDB -NoWarnings | Out-Null

#Document step
Invoke-ApexSqlDocumentStep -Options $options -AsChm -Differential | Out-Null

#Deploy step
Invoke-ApexSqlDeployStep -Options $options -Source $stageDB -DeployType Both -Database $productionDB | Out-Null

#Package step
Invoke-ApexSqlPackageStep -Options $options -nugetVersion "1.0.3" -nugetReleaseNotes "Release_notes_here" | Out-Null

#Notification step
Invoke-ApexSqlNotifyStep -Options $options -DistributionList "*******@gmail.com" -Status completed

#endregion





