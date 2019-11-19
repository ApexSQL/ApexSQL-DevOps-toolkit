Release notes: this document describes changes and enhancements made to ApexSQL DevOps toolkit PowerShell module

--------------------------------------------------------------------------------------------------
Release: 	2019.04.0191
Date: 		November 19, 2019
--------------------------------------------------------------------------------------------------

Enhancements:

- Compare production database with source control
- Validate schema changes
- Format and obfuscate SQL code
- Find and mask sensitive data

Fixes:

- “Cannot validate argument on parameter 'Source_Type'. The argument "sf" does not belong to the set” error is encountered when executing the Build step and a script folder is used as a data source
- “Cannot validate argument on parameter 'Source_Type'. The argument "sf" does not belong to the set” error is encountered when executing the Sync step and a script folder is used as a data source
- “Login failed for user 'username'“error is encountered when executing the Build step and SQL Server authentication method is used for a target database connection
- Additional parameters switch does not work when used with any step execution
- Generated data synchronization script is saved in Windows user folder instead of in the pipeline working folder when the Data sync step is executed

Changes:

- ApexSQL continuous integration example script is updated with the Compare step configuration template 
- ApexSQL continuous delivery example script is updated with the Mask step configuration template

--------------------------------------------------------------------------------------------------
Release: 	2018.09.0058
Date: 		January 15, 2019
--------------------------------------------------------------------------------------------------

Enhancements:

- Installer now automatically removes previous version of PowerShell module
- PowerShell module is now PowerShell gallery code standard compliant

Fixes:

- Executed step fails to find installed ApexSQL application when the application registry path is not default
- Names of output files for the failed steps are listed in the notification email

Changes:

- Default installation path is changed to 'C:\Program Files\WindowsPowershell\Modules'
- Output database folder of the Package step is now 'DatabaseScripts'
- The Build step no longer outputs database build script 
- The Populate step no longer outputs population script
- The Schema sync step is now Sync step
- The Data sync step is now Sync data step

--------------------------------------------------------------------------------------------------
Release: 	2018.04.0056
Date: 		October 11, 2018
--------------------------------------------------------------------------------------------------

Fixes:

- "The property 'NotificationSettings' cannot be found on this object" error is encountered when using the New-ApexSQLNotificationSettings function in PowerShell console

Changes:

- ApexSQL CI/CD toolkit – PowerShell scripts name is changed into ApexSQL DevOps toolkit – PowerShell scripts

--------------------------------------------------------------------------------------------------
Release: 	2018.03.0053
Date: 		September 07, 2018
--------------------------------------------------------------------------------------------------

Enhancements:

- The -ExcludeTables switch is added for the Audit step to exclude desired tables

Fixes:

- NuGet package file is not created when designated file name is used from the global settings

Changes:

- ApexSQL Trigger project file is now mandatory for the Audit step in order to provide repository database information
- Audit step no longer overwrites existing table triggers

--------------------------------------------------------------------------------------------------
Release: 	2017.02.0006
Date: 		July 04, 2018
--------------------------------------------------------------------------------------------------

Enhancements:

- The -PasswordFile switch is added to the New-ApexSqlNotificationSettings, New-ApexSqlSource and New-ApexSqlDatabaseConnection cmdlets to use encrypted password saved in a file

Changes:

- Optional -FillOnlyEmptyTables switch for the Invoke-ApexSqlPopulateStep cmdlet is replaced with the -FillAllTables switch
- The switch -FillOnlyEmptyTables for the Invoke-ApexSqlPopulateStep cmdlet is now set as built-in default

--------------------------------------------------------------------------------------------------
Release: 	2017.02.0005
Date: 		April 26, 2018
--------------------------------------------------------------------------------------------------

Fixes:

- "Bad format of switch: or" error is encountered when execution starts for the Audit step
- "Bad format of switch: on" error is encountered when execution starts for the Review step

--------------------------------------------------------------------------------------------------
Release: 	2017.02.0004
Date: 		December 20, 2017
--------------------------------------------------------------------------------------------------

Enhancements:

- The pipeline job summary log file contains more detailed and descriptive information 
- E-mail notifications contain more detailed and descriptive information about start/end time, executed steps and created output files
- Review step is added to check database objects and scripts by pre-configured rules
- Documentation step can now document database changes only
- NuGet package output
- Support for pushing/fetching NuGet packages to/from a NuGet feed Beep sound is added upon the pipeline completion/failure
- Step in-line new switches to include/exclude output files:
	o [-NoScript] - exclude script output files for the Build, Populate, Schema sync, and Data sync steps 
	o [-NoReport] - exclude report output file for the Test, Review, Schema sync, and Data sync steps
	o [-NoSummary] - exclude summary output files for the Schema sync and Data sync steps
	o [-NoWarnings] - exclude warning output files for the Schema sync and Data sync steps
- Switch for creating output for SQL scripts files added to the populate step [/on]
- Pipeline return codes:
	o 0 – Success – all steps in the pipeline were executed successfully
	o 1 – Failure – one of the steps in the pipeline has failed or an error is encountered 

Fixes:

- The pipeline job summary log file is not attached in an e-mail notification
- The pipeline execution tries to execute the following step even though the previous step has failed 
- Missing information about start/end of the Package and Deploy steps in the pipeline job summary log file and the PowerShell console
- "Cannot process command because of one or more missing mandatory parameters: Source Database" error is encountered when the -Source and -Database switches are replaced with the -ProjectFile switch
- Predefined CI/CD will fail when script file is used as a source
- Success information message is always shown in e-mail notification, even if something failed in the pipeline
- The -ProjectFile switch is not allowed in the Test step, even though ApexSQL Unit Test has the option to create a project file
- SQL Server mixed mode authentication is not working for the Document step
- The $true value is missing for the -FillOnlyEmptyTables switch under the Populate step, causing the predefined CI template pipeline to fail
- Schema sync and Data sync steps don’t provide the return code 102 and the corresponding message when there are no differences
- The predefined CD template pipeline fails if there are no schema/data differences while executing the Deploy step
- The empty password string is not allowed in the Notification step

Changes:

- The package ZIP output type has been replaced with NuGet output type
- Project files can now be included by specifying only project file name without full file path

--------------------------------------------------------------------------------------------------
 Release: 	2017.01.0003
 Date:		June 19, 2017
--------------------------------------------------------------------------------------------------

Changes:

- ApexSQL Doc CLI switch, Output format [/of] is now Output type [/ot]

--------------------------------------------------------------------------------------------------
 Release: 	2017.01.0002
 Date:		March 22, 2017
--------------------------------------------------------------------------------------------------

Enhancements:

- Optional switch added to the Invoke-ApexSqlTestStep cmdlet for installing SQL Cop predefined tests [-InstallSqlCop]

--------------------------------------------------------------------------------------------------
 Release: 	2017.01.0001
 Date:		March 17, 2017
--------------------------------------------------------------------------------------------------

Features:

- PowerShell cmdlets and integration to Bamboo, Jenkins, TeamCity, AppVeyor, GoCD, CruiseControl, Visual Studio Team Services, Team Foundation Server, and any other CI server with PowerShell support
- Continuous integration and continuous delivery PowerShell script templates
- Check for invalid objects
- Build a database directly from source control
- Include static data in builds
- Generate synthetic test data
- Run SQL unit tests
- Synchronize target database with source control
- Automatically create rollback scripts
- Document and report on changes
- Create deployment package
- Archive all output files in a central folder
- Audit sensitive tables with DML triggers
- Customizable data sources
- Support for advanced configuration through individual step project files