# csm-managed-support-version: 2026091701
function Test-ManagedWindowsOwnedRegistryPath {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$RegistryPath)

  $text = $RegistryPath.Trim().Replace('/','\')
  $classesPrefix = 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\'
  if (-not $text.StartsWith($classesPrefix,[System.StringComparison]::OrdinalIgnoreCase)) { return $false }

  $clsidMarker = '\CLSID\'
  $clsidIndex = $text.IndexOf($clsidMarker,[System.StringComparison]::OrdinalIgnoreCase)
  if ($clsidIndex -lt 0) { return $false }

  $tail = $text.Substring($clsidIndex + $clsidMarker.Length)
  $parts = @($tail.Split([char]'\',[System.StringSplitOptions]::RemoveEmptyEntries))
  if ($parts.Count -lt 2) { return $false }

  $parsedGuid = [guid]::Empty
  $guidText = ([string]$parts[0]).Trim().Trim('{','}')
  if (-not [guid]::TryParse($guidText,[ref]$parsedGuid)) { return $false }

  foreach ($part in $parts[1..($parts.Count - 1)]) {
    if (([string]$part).Equals('Elevation',[System.StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}

function ConvertTo-ManagedStartupCommandIdentity {
  [CmdletBinding()]
  param([string]$Value)

  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $text = [Environment]::ExpandEnvironmentVariables($Value.Trim())
  $exe = ''
  $args = ''

  if ($text -match '^"([^"]+?\.exe)"(?:\s+(.*))?$') {
    $exe = $matches[1]
    if ($matches.Count -gt 2) { $args = [string]$matches[2] }
  } elseif ($text -match '^([A-Za-z]:\\.*?\.exe)(?:\s+(.*))?$') {
    $exe = $matches[1]
    if ($matches.Count -gt 2) { $args = [string]$matches[2] }
  } elseif ($text -match '^([^\s]+\.exe)(?:\s+(.*))?$') {
    $exe = $matches[1]
    if ($matches.Count -gt 2) { $args = [string]$matches[2] }
  }

  if (-not $exe) { return $null }
  if ([IO.Path]::IsPathRooted($exe)) {
    try { $exe = [IO.Path]::GetFullPath($exe) } catch { }
  }
  return [pscustomobject]@{ exe=$exe.Trim(); args=$args.Trim() }
}

function Test-ManagedStartupCommandEquivalent {
  [CmdletBinding()]
  param([string]$Expected,[string]$Actual)

  if ([string]$Expected -ceq [string]$Actual) { return $true }
  $expectedIdentity = ConvertTo-ManagedStartupCommandIdentity -Value $Expected
  $actualIdentity = ConvertTo-ManagedStartupCommandIdentity -Value $Actual
  if ($null -eq $expectedIdentity -or $null -eq $actualIdentity) { return $false }
  $exeEqual = ([string]$expectedIdentity.exe).Equals([string]$actualIdentity.exe,[System.StringComparison]::OrdinalIgnoreCase)
  $argsEqual = ([string]$expectedIdentity.args).Equals([string]$actualIdentity.args,[System.StringComparison]::OrdinalIgnoreCase)
  return ($exeEqual -and $argsEqual)
}

function Restore-ManagedStartupEntries {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$ManifestPath,
    [string]$Phase = 'restore',
    [ValidateRange(1,20)][int]$ReconcilePasses = 1,
    [ValidateRange(0,30000)][int]$PassDelayMilliseconds = 0
  )

  if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { return 0 }
  $entries = @(Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json)
  $validEntries = @($entries | Where-Object { $_.path -and $_.name })
  if (-not $validEntries.Count) { return 0 }

  for ($pass = 1; $pass -le $ReconcilePasses; $pass++) {
    foreach ($entry in $validEntries) {
      $entryPath = [string]$entry.path
      $entryName = [string]$entry.name
      $entryValue = [string]$entry.value
      $entryType = if ([string]$entry.kind -eq 'ExpandString') { 'ExpandString' } else { 'String' }

      New-Item -Path $entryPath -Force | Out-Null
      New-ItemProperty -Path $entryPath -Name $entryName -Value $entryValue -PropertyType $entryType -Force | Out-Null
      $item = Get-Item -LiteralPath $entryPath -ErrorAction Stop
      $actual = [string]$item.GetValue($entryName,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      if ($actual -ne $entryValue) {
        throw "Managed startup reconciliation failed phase=$Phase pass=$pass path=$entryPath name=$entryName expected=[$entryValue] actual=[$actual]"
      }
      Write-Host "MANAGED_WINDOWS_STARTUP_RECONCILE_OK phase=$Phase pass=$pass/$ReconcilePasses path=$entryPath name=$entryName"
    }
    if ($pass -lt $ReconcilePasses -and $PassDelayMilliseconds -gt 0) {
      Start-Sleep -Milliseconds $PassDelayMilliseconds
    }
  }

  # One last read-only check after the last write pass.
  foreach ($entry in $validEntries) {
    $entryPath = [string]$entry.path
    $entryName = [string]$entry.name
    $entryValue = [string]$entry.value
    $item = Get-Item -LiteralPath $entryPath -ErrorAction Stop
    $actual = [string]$item.GetValue($entryName,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($actual -ne $entryValue) {
      throw "Managed startup final verification failed phase=$Phase path=$entryPath name=$entryName expected=[$entryValue] actual=[$actual]"
    }
  }
  return [int]$validEntries.Count
}

function Register-ManagedScheduledTaskXml {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$TaskName,
    [string]$TaskPath = '\',
    [Parameter(Mandatory=$true)][string]$Xml,
    [hashtable]$SourceSidMap = @{},
    [hashtable]$TargetSidByName = @{}
  )

  if ([string]::IsNullOrWhiteSpace($TaskPath)) { $TaskPath = '\' }
  foreach ($oldSid in @($SourceSidMap.Keys)) {
    if ($oldSid -and $SourceSidMap[$oldSid]) { $Xml = $Xml.Replace([string]$oldSid,[string]$SourceSidMap[$oldSid]) }
  }

  [xml]$taskXml = $Xml
  $wellKnown = @{
    'SYSTEM'='S-1-5-18'; 'NT AUTHORITY\SYSTEM'='S-1-5-18'; 'LOCALSYSTEM'='S-1-5-18'; 'NT AUTHORITY\LOCALSYSTEM'='S-1-5-18'; 'S-1-5-18'='S-1-5-18'
    'LOCAL SERVICE'='S-1-5-19'; 'NT AUTHORITY\LOCAL SERVICE'='S-1-5-19'; 'S-1-5-19'='S-1-5-19'
    'NETWORK SERVICE'='S-1-5-20'; 'NT AUTHORITY\NETWORK SERVICE'='S-1-5-20'; 'S-1-5-20'='S-1-5-20'
    'BUILTIN\ADMINISTRATORS'='S-1-5-32-544'; 'S-1-5-32-544'='S-1-5-32-544'
    'BUILTIN\USERS'='S-1-5-32-545'; 'S-1-5-32-545'='S-1-5-32-545'
  }

  $principalNodes = @($taskXml.SelectNodes("//*[local-name()='Principal']/*[local-name()='UserId' or local-name()='GroupId']"))
  foreach ($node in $principalNodes) {
    $original = ([string]$node.InnerText).Trim()
    if (-not $original) { continue }
    $mapped = ''
    if ($wellKnown.ContainsKey($original)) {
      $mapped = [string]$wellKnown[$original]
    } elseif ($SourceSidMap.ContainsKey($original)) {
      $mapped = [string]$SourceSidMap[$original]
    } elseif ($original -match '^[^\\]+\\(?<name>[^\\]+)$' -and $TargetSidByName.ContainsKey($matches.name)) {
      $mapped = [string]$TargetSidByName[$matches.name]
    }
    if ($mapped -and -not $original.Equals($mapped,[System.StringComparison]::OrdinalIgnoreCase)) {
      $node.InnerText = $mapped
      Write-Host "MANAGED_WINDOWS_TASK_PRINCIPAL_REWRITE task=$TaskName old=$original new=$mapped"
    }
  }

  $userNode = $taskXml.SelectSingleNode("//*[local-name()='Principal']/*[local-name()='UserId']")
  $registrationUser = ''
  if ($null -ne $userNode) {
    $principalValue = ([string]$userNode.InnerText).Trim()
    $registrationUser = switch ($principalValue) {
      'S-1-5-18' { 'SYSTEM' }
      'S-1-5-19' { 'LOCAL SERVICE' }
      'S-1-5-20' { 'NETWORK SERVICE' }
      default { '' }
    }
  }

  $normalizedXml = $taskXml.OuterXml
  if ($registrationUser) {
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Xml $normalizedXml -User $registrationUser -Force -ErrorAction Stop | Out-Null
    Write-Host "MANAGED_WINDOWS_TASK_SERVICE_ACCOUNT_OVERRIDE task=$TaskName user=$registrationUser"
  } else {
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Xml $normalizedXml -Force -ErrorAction Stop | Out-Null
  }

  $registered = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
  if ($null -eq $registered) { throw "Scheduled task registration verification failed: $TaskPath$TaskName" }
  if ($registrationUser) {
    $actualPrincipal = ([string]$registered.Principal.UserId).Trim()
    $expectedSid = switch ($registrationUser) {
      'SYSTEM' { 'S-1-5-18' }
      'LOCAL SERVICE' { 'S-1-5-19' }
      'NETWORK SERVICE' { 'S-1-5-20' }
      default { '' }
    }
    $accepted = @($registrationUser,$expectedSid,"NT AUTHORITY\$registrationUser")
    if ($actualPrincipal -and -not ($accepted | Where-Object { $actualPrincipal.Equals($_,[System.StringComparison]::OrdinalIgnoreCase) })) {
      throw "Scheduled task principal verification failed task=$TaskName expected=$registrationUser/$expectedSid actual=$actualPrincipal"
    }
  }
  Write-Host "MANAGED_WINDOWS_SCHEDULED_TASK_RESTORED path=$TaskPath name=$TaskName"
  return $registered
}
