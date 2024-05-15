#Requires -version 5 -runasadministrator

using module ActiveDirectory
using module ScheduledTasks

#### PARAMETERS ####

$TaskName = "NTAuth Guard"
$TaskPath = "\"

$EventLog = "Application"
$EventSource = "NTAuthGuard"

$ServiceAccount = "CORP\s0ntauthguard$"
$ScriptPath = "\\corp.contoso.com\netlogon\NTAuth\Invoke-NTAuthCleanup.ps1"
$WhiteListPath = "\\corp.contoso.com\netlogon\NTAuth\whitelist.txt"

#### END PARAMETERS ####

$TaskExists = $false
Try
{
    $Task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    $TaskExists = $true
}
Catch
{
    # Do nothing, check $TaskExists in next step
}

$EventFilter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and Task = 14081 and (band(Keywords,9007199254740992)) and (EventID=5136)] and EventData[Data[@Name='OperationType']='%%14674' and Data[@Name='ObjectDN']='%NTAUTH%']]</Select>
  </Query>
</QueryList>
"@

# Check if event source exists and create it if not
If (![System.Diagnostics.EventLog]::SourceExists($EventSource))
{
    [System.Diagnostics.EventLog]::CreateEventSource($EventSource, $EventLog)
}

If (!$TaskExists)
{
    # Get RootDSE
    $RootDse = Get-ADRootDSE

    # Construct NTAuth distinguished name
    $NTAuthDN = 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{0}' -f $RootDse.configurationNamingContext

    # Get name of current forest
    $Forest = Get-ADForest | Select-Object -ExpandProperty RootDomain

    # Replace the %NTAUTH% placeholder in the event filter with the correct distinguished name to the NTAuth object
    $EventFilter = $EventFilter -replace "%NTAUTH%", $NTAuthDN

    # PowerShell.exe arguments
    $ActionArguments = '-noprofile -executionpolicy Bypass -file "{0}" -FilePath "{1}" -ForestDomainName {2} -AllowImplicitRenewedCertificates' -f $ScriptPath, $WhiteListPath, $Forest

    # Create task properties
    $Principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -RunLevel Limited -LogonType Password
    $Action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $ActionArguments
    $DailyTrigger = New-ScheduledTaskTrigger -Daily -At 00:00
    $FiveMinuteTrigger = New-ScheduledTaskTrigger -Once -RepetitionDuration 1.00:00:00 -RepetitionInterval 00:05 -At 00:00:00
    $DailyTrigger.Repetition = $FiveMinuteTrigger.Repetition

    # Event triggers must be created manually through CIM objects
    $CimTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger `
                                    -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskEventTrigger
 
    $EventTrigger = New-CimInstance -CimClass $CimTriggerClass -ClientOnly
    $EventTrigger.Subscription = $EventFilter
    $EventTrigger.ExecutionTimeLimit = 'PT5M'
    $EventTrigger.Enabled = $true

    # Set the execution time limit to 1 minute, and allow new instances to be queued
    $Settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -ExecutionTimeLimit ([TimeSpan]::new(0, 1, 0)) -MultipleInstances Queue

    # Register the scheduled task
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Principal $Principal -Action $Action -Settings $Settings -Trigger $DailyTrigger, $EventTrigger 
}