# csm-managed-support-version: 2026091713
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

function Test-ManagedWindowsRuntimeRegistryPath {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$RegistryPath)

  $text = $RegistryPath.Trim().Replace('/','\')
  $runtimePrefixes = @(
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityCRL\NegativeCache',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityCRL\ThrottleCache',
    'HKEY_CURRENT_USER\SOFTWARE\Microsoft\RestartManager',
    'HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\MrtCache'
  )
  foreach ($prefix in $runtimePrefixes) {
    if ($text.Equals($prefix,[System.StringComparison]::OrdinalIgnoreCase) -or
        $text.StartsWith($prefix + '\',[System.StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}

function Test-ManagedVolatileAclMissingLine {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Line)

  $text = $Line.Trim()
  if ([string]::IsNullOrWhiteSpace($text)) { return $false }

  # icacls reports a missing object as "<path>: The system cannot find ...".
  # Classify only clearly disposable runtime objects. Durable configuration files
  # must remain strict so ACL restore still catches a genuinely incomplete capsule.
  $pathText = $text
  $marker = ': The system cannot find'
  $markerIndex = $text.IndexOf($marker,[System.StringComparison]::OrdinalIgnoreCase)
  if ($markerIndex -gt 1) { $pathText = $text.Substring(0,$markerIndex).Trim().Trim('"') }
  $normalized = $pathText.Replace('/','\')

  if ($normalized -match '(?i)[\\](?:log|logs|cache|caches|temp|tmp|crash|crashes|sentry)(?:[\\]|$)') { return $true }
  if ($normalized -match '(?i)\.run(?:[\\]|\.lock|:|$)|\.lock(?:[\\]|:|$)') { return $true }

  $leaf = [IO.Path]::GetFileName($normalized)
  if ([string]::IsNullOrWhiteSpace($leaf)) { return $false }
  if ($leaf -match '(?i)^(?:cache|cached)(?:[_\-.].*)?$') { return $true }
  if ($leaf -match '(?i)\.(?:tmp|temp|cache|lock)$') { return $true }
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

function Get-ManagedStartupServiceBacking {
  [CmdletBinding()]
  param(
    [string]$StartupValue,
    [object[]]$Services = @()
  )

  $startupIdentity = ConvertTo-ManagedStartupCommandIdentity -Value $StartupValue
  if ($null -eq $startupIdentity -or [string]::IsNullOrWhiteSpace([string]$startupIdentity.exe)) { return $null }

  foreach ($service in @($Services)) {
    if ($null -eq $service) { continue }
    $start = -1
    try { $start = [int]$service.start } catch { $start = -1 }
    if ($start -ne 2) { continue }
    $serviceIdentity = ConvertTo-ManagedStartupCommandIdentity -Value ([string]$service.path)
    if ($null -eq $serviceIdentity -or [string]::IsNullOrWhiteSpace([string]$serviceIdentity.exe)) { continue }
    if (([string]$startupIdentity.exe).Equals([string]$serviceIdentity.exe,[System.StringComparison]::OrdinalIgnoreCase)) {
      return $service
    }
  }
  return $null
}

function ConvertTo-ManagedSoftwareIdentityToken {
  [CmdletBinding()]
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
  return (($Value.ToLowerInvariant()) -replace '[^\p{L}\p{Nd}]','')
}

function Get-ManagedSoftwareIdentityTokens {
  [CmdletBinding()]
  param([string[]]$Values = @())

  $tokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($value in @($Values)) {
    if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
    $full = ConvertTo-ManagedSoftwareIdentityToken -Value ([string]$value)
    if ($full.Length -ge 4) { [void]$tokens.Add($full) }
    foreach ($part in @(([string]$value) -split '[\.\-_\s\\/\(\)\[\]]+')) {
      $token = ConvertTo-ManagedSoftwareIdentityToken -Value $part
      if ($token.Length -ge 4) { [void]$tokens.Add($token) }
    }
  }
  return @($tokens | Sort-Object Length -Descending -Unique)
}

function Find-ManagedPackageForApplication {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]$Application,
    [object[]]$PackagePlan = @()
  )

  $registryLeaf = (([string]$Application.registry_path -split '\\') | Select-Object -Last 1)
  $appTokens = @(Get-ManagedSoftwareIdentityTokens -Values @(
    [string]$Application.name,
    [string]$registryLeaf,
    [IO.Path]::GetFileName(([string]$Application.install_location).TrimEnd('\'))
  ))
  if (-not $appTokens.Count) { return $null }

  $best = $null
  $bestScore = -1
  foreach ($package in @($PackagePlan)) {
    if ($null -eq $package) { continue }
    $packageTokens = @(Get-ManagedSoftwareIdentityTokens -Values @([string]$package.package_id,[string]$package.display_name))
    foreach ($packageToken in $packageTokens) {
      foreach ($appToken in $appTokens) {
        $score = -1
        if ($appToken.Equals($packageToken,[System.StringComparison]::OrdinalIgnoreCase)) {
          $score = 1000 + $packageToken.Length
        } elseif ($packageToken.Length -ge 5 -and (
          $appToken.IndexOf($packageToken,[System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
          $packageToken.IndexOf($appToken,[System.StringComparison]::OrdinalIgnoreCase) -ge 0
        )) {
          $score = 100 + [math]::Min($appToken.Length,$packageToken.Length)
        }
        if ($score -gt $bestScore) { $bestScore = $score; $best = $package }
      }
    }
  }
  if ($bestScore -lt 0) { return $null }
  return $best
}

function Test-ManagedApplicationUsesRehydration {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]$Application,
    [object[]]$ApplicationPlan = @()
  )

  $registryPath = ([string]$Application.registry_path).Trim()
  if (-not $registryPath) { return $false }
  foreach ($entry in @($ApplicationPlan)) {
    if ($null -eq $entry -or [string]$entry.strategy -ne 'rehydrate') { continue }
    if ($registryPath.Equals(([string]$entry.registry_path).Trim(),[System.StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}

function Test-ManagedPathUsesRehydration {
  [CmdletBinding()]
  param(
    [string]$Path,
    [object[]]$ApplicationPlan = @()
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  try { $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"')) } catch { $expanded = $Path }
  $pathToken = ConvertTo-ManagedSoftwareIdentityToken -Value $expanded
  $pathParts = @($expanded -split '[\\/]+')
  $pathTokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($part in $pathParts) {
    $token = ConvertTo-ManagedSoftwareIdentityToken -Value $part
    if ($token.Length -ge 4) { [void]$pathTokens.Add($token) }
  }
  foreach ($entry in @($ApplicationPlan)) {
    if ($null -eq $entry -or [string]$entry.strategy -ne 'rehydrate') { continue }
    $tokens = @(Get-ManagedSoftwareIdentityTokens -Values @([string]$entry.package_id,[string]$entry.app_name))
    foreach ($token in $tokens) {
      if ($pathTokens.Contains($token)) { return $true }
      if ($token.Length -ge 5 -and $pathToken.IndexOf($token,[System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
  }
  return $false
}

function New-ManagedSoftwareRehydrationPlan {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$BaselineRoot,
    [Parameter(Mandatory=$true)][string]$StateRoot,
    [object[]]$AppDelta = @()
  )

  New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
  $packages = [System.Collections.Generic.List[object]]::new()

  function Add-ManagedPackagePlanEntry {
    param([string]$Manager,[string]$PackageId,[string]$Version,[string]$Source,[string]$DisplayName='')
    if ([string]::IsNullOrWhiteSpace($Manager) -or [string]::IsNullOrWhiteSpace($PackageId)) { return }
    $existing = $packages | Where-Object {
      ([string]$_.manager).Equals($Manager,[System.StringComparison]::OrdinalIgnoreCase) -and
      ([string]$_.package_id).Equals($PackageId,[System.StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    if ($null -ne $existing) { return }
    [void]$packages.Add([pscustomobject]@{
      manager=$Manager; package_id=$PackageId; version=$Version; source=$Source;
      display_name=$DisplayName; strict_version=(-not [string]::IsNullOrWhiteSpace($Version))
    })
  }

  if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
    try {
      $currentPath = Join-Path $StateRoot 'winget-current.json'
      & winget.exe export -o $currentPath --include-versions --accept-source-agreements --disable-interactivity | Out-Host
      if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
        $current = Get-Content -LiteralPath $currentPath -Raw | ConvertFrom-Json
        $baselineVersions = @{}
        $baselinePath = Join-Path $BaselineRoot 'winget.json'
        if (Test-Path -LiteralPath $baselinePath -PathType Leaf) {
          $baseline = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
          foreach ($source in @($baseline.Sources)) {
            foreach ($pkg in @($source.Packages)) {
              if ($pkg.PackageIdentifier) { $baselineVersions[[string]$pkg.PackageIdentifier] = [string]$pkg.Version }
            }
          }
        }
        $deltaSources = [System.Collections.Generic.List[object]]::new()
        foreach ($source in @($current.Sources)) {
          $deltaPackages = [System.Collections.Generic.List[object]]::new()
          foreach ($pkg in @($source.Packages)) {
            $id = ([string]$pkg.PackageIdentifier).Trim()
            if (-not $id) { continue }
            $version = ([string]$pkg.Version).Trim()
            $changed = -not $baselineVersions.ContainsKey($id) -or -not ([string]$baselineVersions[$id]).Equals($version,[System.StringComparison]::OrdinalIgnoreCase)
            if (-not $changed) { continue }
            [void]$deltaPackages.Add($pkg)
            $sourceId = if ($source.SourceDetails.Identifier) { [string]$source.SourceDetails.Identifier } elseif ($source.SourceDetails.Name) { [string]$source.SourceDetails.Name } else { 'winget' }
            Add-ManagedPackagePlanEntry -Manager 'winget' -PackageId $id -Version $version -Source $sourceId
          }
          if ($deltaPackages.Count) { [void]$deltaSources.Add([pscustomobject]@{ Packages=@($deltaPackages); SourceDetails=$source.SourceDetails }) }
        }
        if ($deltaSources.Count) {
          $delta = [ordered]@{}
          if ($current.PSObject.Properties.Name -contains '$schema') { $delta['$schema'] = $current.'$schema' }
          $delta['CreationDate'] = [DateTime]::UtcNow.ToString('o')
          $delta['Sources'] = @($deltaSources)
          ConvertTo-Json -InputObject $delta -Depth 12 | Set-Content -LiteralPath (Join-Path $StateRoot 'winget.json') -Encoding UTF8
        }
      }
      Remove-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue
    } catch { Write-Warning "MANAGED_WINDOWS_REHYDRATION_WINGET_PLAN_SKIPPED reason=$($_.Exception.Message)" }
  }

  if (Get-Command choco.exe -ErrorAction SilentlyContinue) {
    try {
      $baselineVersions = @{}
      $baselinePath = Join-Path $BaselineRoot 'choco-packages.txt'
      if (Test-Path -LiteralPath $baselinePath -PathType Leaf) {
        foreach ($line in Get-Content -LiteralPath $baselinePath) {
          $parts = ([string]$line) -split '\|', 2
          if ($parts.Count -gt 0 -and $parts[0].Trim()) {
            $baselineVersions[$parts[0].Trim().ToLowerInvariant()] = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
          }
        }
      }
      $currentChoco = @(& choco.exe list --local-only --limit-output 2>$null)
      if ($LASTEXITCODE -ne 0) { $currentChoco = @(& choco.exe list --limit-output 2>$null) }
      $deltaChoco = [System.Collections.Generic.List[string]]::new()
      foreach ($line in $currentChoco) {
        $parts = ([string]$line) -split '\|', 2
        if ($parts.Count -lt 1) { continue }
        $name = $parts[0].Trim()
        if (-not $name -or $name.StartsWith('Chocolatey ',[System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $version = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
        $key = $name.ToLowerInvariant()
        $changed = -not $baselineVersions.ContainsKey($key) -or -not ([string]$baselineVersions[$key]).Equals($version,[System.StringComparison]::OrdinalIgnoreCase)
        if (-not $changed) { continue }
        [void]$deltaChoco.Add([string]$line)
        Add-ManagedPackagePlanEntry -Manager 'choco' -PackageId $name -Version $version -Source 'chocolatey'
      }
      if ($deltaChoco.Count) { $deltaChoco | Set-Content -LiteralPath (Join-Path $StateRoot 'choco-packages.txt') -Encoding UTF8 }
    } catch { Write-Warning "MANAGED_WINDOWS_REHYDRATION_CHOCO_PLAN_SKIPPED reason=$($_.Exception.Message)" }
  }

  if (Get-Command scoop -ErrorAction SilentlyContinue) {
    try {
      $currentPath = Join-Path $StateRoot 'scoop-current.json'
      & scoop export | Set-Content -LiteralPath $currentPath -Encoding UTF8
      $current = Get-Content -LiteralPath $currentPath -Raw | ConvertFrom-Json
      $baselineVersions = @{}
      $baselinePath = Join-Path $BaselineRoot 'scoop.json'
      if (Test-Path -LiteralPath $baselinePath -PathType Leaf) {
        $baseline = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
        foreach ($app in @($baseline.apps)) { if ($app.Name) { $baselineVersions[[string]$app.Name] = [string]$app.Version } }
      }
      $deltaApps = [System.Collections.Generic.List[object]]::new()
      foreach ($app in @($current.apps)) {
        $name = ([string]$app.Name).Trim()
        if (-not $name) { continue }
        $version = ([string]$app.Version).Trim()
        $changed = -not $baselineVersions.ContainsKey($name) -or -not ([string]$baselineVersions[$name]).Equals($version,[System.StringComparison]::OrdinalIgnoreCase)
        if (-not $changed) { continue }
        [void]$deltaApps.Add($app)
        Add-ManagedPackagePlanEntry -Manager 'scoop' -PackageId $name -Version $version -Source ([string]$app.Source)
      }
      if ($deltaApps.Count) {
        [pscustomobject]@{ buckets=$current.buckets; apps=@($deltaApps) } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $StateRoot 'scoop.json') -Encoding UTF8
      }
      Remove-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue
    } catch { Write-Warning "MANAGED_WINDOWS_REHYDRATION_SCOOP_PLAN_SKIPPED reason=$($_.Exception.Message)" }
  }

  $applicationPlan = [System.Collections.Generic.List[object]]::new()
  $selectedPackages = [System.Collections.Generic.List[object]]::new()
  $selectedPackageKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($app in @($AppDelta)) {
    $package = Find-ManagedPackageForApplication -Application $app -PackagePlan @($packages)
    if ($null -ne $package) {
      $packageKey = "$([string]$package.manager)|$([string]$package.package_id)"
      if ($selectedPackageKeys.Add($packageKey)) { [void]$selectedPackages.Add($package) }
      [void]$applicationPlan.Add([pscustomobject]@{
        registry_path=[string]$app.registry_path; app_name=[string]$app.name; app_version=[string]$app.version;
        strategy='rehydrate'; manager=[string]$package.manager; package_id=[string]$package.package_id; package_version=[string]$package.version
      })
      Write-Host "MANAGED_WINDOWS_APP_PLAN strategy=rehydrate app=$($app.name) manager=$($package.manager) package=$($package.package_id) version=$($package.version)"
    } else {
      [void]$applicationPlan.Add([pscustomobject]@{
        registry_path=[string]$app.registry_path; app_name=[string]$app.name; app_version=[string]$app.version;
        strategy='payload'; manager=''; package_id=''; package_version=''
      })
      Write-Host "MANAGED_WINDOWS_APP_PLAN strategy=payload app=$($app.name) version=$($app.version)"
    }
  }

  # Only keep one preferred reconstruction source per installed application. A complete
  # software capsule is still authoritative, so duplicating the same app through winget
  # and Chocolatey only adds restore time and can perturb installer state.
  ConvertTo-Json -InputObject @($selectedPackages) -Depth 7 | Set-Content -LiteralPath (Join-Path $StateRoot 'rehydration-plan.json') -Encoding UTF8
  ConvertTo-Json -InputObject @($applicationPlan) -Depth 7 | Set-Content -LiteralPath (Join-Path $StateRoot 'application-plan.json') -Encoding UTF8
  $fallbackCount = @($applicationPlan | Where-Object { [string]$_.strategy -eq 'payload' }).Count
  $rehydrateCount = @($applicationPlan | Where-Object { [string]$_.strategy -eq 'rehydrate' }).Count
  Write-Host "MANAGED_WINDOWS_REHYDRATION_PLAN candidates=$($packages.Count) selected=$($selectedPackages.Count) apps=$($applicationPlan.Count) rehydrateApps=$rehydrateCount fallbackApps=$fallbackCount"
  return [pscustomobject]@{ packages=@($selectedPackages); applications=@($applicationPlan); rehydrate_apps=$rehydrateCount; fallback_apps=$fallbackCount }
}

function Invoke-ManagedSoftwareRehydrate {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$StateRoot)

  $planPath = Join-Path $StateRoot 'rehydration-plan.json'
  if (-not (Test-Path -LiteralPath $planPath -PathType Leaf)) {
    Write-Host 'MANAGED_WINDOWS_REHYDRATION_NONE'
    return [pscustomobject]@{ total=0; restored=0; failed=0; fallback_required=$false; failures=@() }
  }
  $plan = @(Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json)
  if (-not $plan.Count) {
    Write-Host 'MANAGED_WINDOWS_REHYDRATION_NONE'
    return [pscustomobject]@{ total=0; restored=0; failed=0; fallback_required=$false; failures=@() }
  }

  $restored = 0
  $failed = 0
  $failures = [System.Collections.Generic.List[string]]::new()

  $wingetEntries = @($plan | Where-Object { [string]$_.manager -eq 'winget' })
  if ($wingetEntries.Count) {
    $manifest = Join-Path $StateRoot 'winget.json'
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget -or -not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
      $failed += $wingetEntries.Count
      [void]$failures.Add("winget prerequisites missing packages=$($wingetEntries.Count)")
      Write-Warning "MANAGED_WINDOWS_REHYDRATE_FALLBACK manager=winget reason=prerequisites-missing packages=$($wingetEntries.Count)"
    } else {
      $ok = $false
      for ($attempt=1; $attempt -le 2 -and -not $ok; $attempt++) {
        & $winget.Source import -i $manifest --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Host
        if ($LASTEXITCODE -eq 0) { $ok = $true; break }
        Write-Warning "MANAGED_WINDOWS_REHYDRATE_RETRY manager=winget attempt=$attempt exit=$LASTEXITCODE"
        Start-Sleep -Seconds (3 * $attempt)
      }
      if ($ok) {
        $restored += $wingetEntries.Count
        Write-Host "MANAGED_WINDOWS_REHYDRATE_OK manager=winget packages=$($wingetEntries.Count)"
      } else {
        $failed += $wingetEntries.Count
        [void]$failures.Add("winget import failed packages=$($wingetEntries.Count)")
        Write-Warning "MANAGED_WINDOWS_REHYDRATE_FALLBACK manager=winget reason=import-failed packages=$($wingetEntries.Count)"
      }
    }
  }

  $chocoEntries = @($plan | Where-Object { [string]$_.manager -eq 'choco' })
  if ($chocoEntries.Count) {
    $choco = Get-Command choco.exe -ErrorAction SilentlyContinue
    if (-not $choco) {
      $failed += $chocoEntries.Count
      [void]$failures.Add("choco prerequisites missing packages=$($chocoEntries.Count)")
      Write-Warning "MANAGED_WINDOWS_REHYDRATE_FALLBACK manager=choco reason=prerequisites-missing packages=$($chocoEntries.Count)"
    } else {
      foreach ($entry in $chocoEntries) {
        $id = ([string]$entry.package_id).Trim()
        $version = ([string]$entry.version).Trim()
        $ok = $false
        for ($attempt=1; $attempt -le 2 -and -not $ok; $attempt++) {
          $args = @('install',$id,'-y','--no-progress','--allow-downgrade','--force')
          if ($version) { $args += @('--version',$version) }
          & $choco.Source @args | Out-Host
          if ($LASTEXITCODE -eq 0) { $ok=$true; break }
          Write-Warning "MANAGED_WINDOWS_REHYDRATE_RETRY manager=choco package=$id version=$version attempt=$attempt exit=$LASTEXITCODE"
          Start-Sleep -Seconds (3 * $attempt)
        }
        if ($ok) {
          $restored++
          Write-Host "MANAGED_WINDOWS_REHYDRATE_OK manager=choco package=$id version=$version"
        } else {
          $failed++
          [void]$failures.Add("choco package=$id version=$version")
          Write-Warning "MANAGED_WINDOWS_REHYDRATE_FALLBACK manager=choco package=$id version=$version reason=install-failed"
        }
      }
    }
  }

  $scoopEntries = @($plan | Where-Object { [string]$_.manager -eq 'scoop' })
  if ($scoopEntries.Count) {
    $manifest = Join-Path $StateRoot 'scoop.json'
    $scoop = Get-Command scoop -ErrorAction SilentlyContinue
    if (-not $scoop -or -not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
      $failed += $scoopEntries.Count
      [void]$failures.Add("scoop prerequisites missing packages=$($scoopEntries.Count)")
      Write-Warning "MANAGED_WINDOWS_REHYDRATE_FALLBACK manager=scoop reason=prerequisites-missing packages=$($scoopEntries.Count)"
    } else {
      $ok = $false
      for ($attempt=1; $attempt -le 2 -and -not $ok; $attempt++) {
        & $scoop.Source import $manifest | Out-Host
        if ($LASTEXITCODE -eq 0) { $ok=$true; break }
        Write-Warning "MANAGED_WINDOWS_REHYDRATE_RETRY manager=scoop attempt=$attempt exit=$LASTEXITCODE"
        Start-Sleep -Seconds (3 * $attempt)
      }
      if ($ok) {
        $restored += $scoopEntries.Count
        Write-Host "MANAGED_WINDOWS_REHYDRATE_OK manager=scoop packages=$($scoopEntries.Count)"
      } else {
        $failed += $scoopEntries.Count
        [void]$failures.Add("scoop import failed packages=$($scoopEntries.Count)")
        Write-Warning "MANAGED_WINDOWS_REHYDRATE_FALLBACK manager=scoop reason=import-failed packages=$($scoopEntries.Count)"
      }
    }
  }

  $known = $wingetEntries.Count + $chocoEntries.Count + $scoopEntries.Count
  if ($known -lt $plan.Count) {
    $unknown = $plan.Count - $known
    $failed += $unknown
    [void]$failures.Add("unknown package manager entries=$unknown")
    Write-Warning "MANAGED_WINDOWS_REHYDRATE_FALLBACK manager=unknown packages=$unknown"
  }

  $fallbackRequired = ($failed -gt 0)
  $result = [pscustomobject]@{
    created_at=[DateTime]::UtcNow.ToString('o')
    total=$plan.Count
    restored=$restored
    failed=$failed
    fallback_required=$fallbackRequired
    failures=@($failures)
    packages=$plan
  }
  $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $StateRoot 'rehydration-result.json') -Encoding UTF8
  Write-Host "MANAGED_WINDOWS_REHYDRATION_COMPLETE total=$($plan.Count) restored=$restored failed=$failed fallbackRequired=$fallbackRequired"
  # Package-manager failure is advisory because the full software capsule is authoritative.
  # Normalize the native-process status so pwsh/GitHub does not convert an intentional
  # fallback into a failed workflow step.
  $global:LASTEXITCODE = 0
  return $result
}
function Restore-ManagedStartupEntries {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$ManifestPath,
    [string]$Phase = 'restore',
    [ValidateRange(1,20)][int]$ReconcilePasses = 1,
    [ValidateRange(0,30000)][int]$PassDelayMilliseconds = 0,
    [switch]$SkipFinalVerification
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
        if ($pass -lt $ReconcilePasses) {
          Write-Warning "MANAGED_WINDOWS_STARTUP_RECONCILE_RETRY phase=$Phase pass=$pass/$ReconcilePasses path=$entryPath name=$entryName expected=[$entryValue] actual=[$actual]"
          continue
        }
        throw "Managed startup reconciliation failed phase=$Phase pass=$pass path=$entryPath name=$entryName expected=[$entryValue] actual=[$actual]"
      }
      Write-Host "MANAGED_WINDOWS_STARTUP_RECONCILE_OK phase=$Phase pass=$pass/$ReconcilePasses path=$entryPath name=$entryName"
    }
    if ($pass -lt $ReconcilePasses -and $PassDelayMilliseconds -gt 0) {
      Start-Sleep -Milliseconds $PassDelayMilliseconds
    }
  }

  # One last read-only check after the last write pass. The early restore phase can
  # deliberately defer this check because freshly installed applications may still be
  # normalizing their own Run entries. The later final-stable phase remains strict.
  $deferredUnstable = 0
  foreach ($entry in $validEntries) {
    $entryPath = [string]$entry.path
    $entryName = [string]$entry.name
    $entryValue = [string]$entry.value
    $item = Get-Item -LiteralPath $entryPath -ErrorAction Stop
    $actual = [string]$item.GetValue($entryName,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($actual -ne $entryValue) {
      if (-not $SkipFinalVerification) {
        throw "Managed startup final verification failed phase=$Phase path=$entryPath name=$entryName expected=[$entryValue] actual=[$actual]"
      }
      $deferredUnstable++
      Write-Warning "MANAGED_WINDOWS_STARTUP_FINAL_VERIFICATION_DEFERRED_ENTRY phase=$Phase path=$entryPath name=$entryName expected=[$entryValue] actual=[$actual]"
    }
  }
  if ($SkipFinalVerification) {
    Write-Host "MANAGED_WINDOWS_STARTUP_FINAL_VERIFICATION_DEFERRED phase=$Phase unstable=$deferredUnstable total=$($validEntries.Count)"
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

  # Identity-bearing UserId/GroupId nodes can appear both under Principals and under
  # trigger definitions (for example LogonTrigger/UserId). Raw scheduler XML must
  # migrate all of them when a local account was renamed between ephemeral VMs.
  $identityNodes = @($taskXml.SelectNodes("//*[local-name()='UserId' or local-name()='GroupId']"))
  foreach ($node in $identityNodes) {
    $original = ([string]$node.InnerText).Trim()
    if (-not $original) { continue }
    $mapped = ''
    if ($wellKnown.ContainsKey($original)) {
      $mapped = [string]$wellKnown[$original]
    } elseif ($SourceSidMap.ContainsKey($original)) {
      $mapped = [string]$SourceSidMap[$original]
    } elseif ($original -match '^[^\\]+\\(?<name>[^\\]+)$' -and $TargetSidByName.ContainsKey($matches.name)) {
      $mapped = [string]$TargetSidByName[$matches.name]
    } elseif ($TargetSidByName.ContainsKey($original)) {
      # Export-ScheduledTask may persist a local principal as a bare user name.
      # Map it to the target SID just like MACHINE\user so VM/account renames are portable.
      $mapped = [string]$TargetSidByName[$original]
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

  # Raw task files can retain the creator's old MACHINE\user in RegistrationInfo/Author
  # after the managed account is renamed. Some hosted Task Scheduler APIs attempt to
  # resolve that descriptive field during registration, so normalize it for service tasks.
  if ($registrationUser) {
    $authorNode = $taskXml.SelectSingleNode("//*[local-name()='RegistrationInfo']/*[local-name()='Author']")
    if ($null -ne $authorNode) {
      $oldAuthor = ([string]$authorNode.InnerText).Trim()
      if (-not $oldAuthor.Equals($registrationUser,[System.StringComparison]::OrdinalIgnoreCase)) {
        $authorNode.InnerText = $registrationUser
        Write-Host "MANAGED_WINDOWS_TASK_AUTHOR_REWRITE task=$TaskName old=$oldAuthor new=$registrationUser"
      }
    }
  }

  $normalizedXml = $taskXml.OuterXml
  $registeredBy = 'powershell'
  try {
    if ($registrationUser) {
      Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Xml $normalizedXml -User $registrationUser -Force -ErrorAction Stop | Out-Null
      Write-Host "MANAGED_WINDOWS_TASK_SERVICE_ACCOUNT_OVERRIDE task=$TaskName user=$registrationUser"
    } else {
      Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Xml $normalizedXml -Force -ErrorAction Stop | Out-Null
    }
  } catch {
    $primaryError = $_.Exception.Message
    $taskFullName = if ($TaskPath -eq '\') { "\$TaskName" } else { ($TaskPath.TrimEnd('\') + '\' + $TaskName) }
    if (-not $taskFullName.StartsWith('\')) { $taskFullName = '\' + $taskFullName }
    $taskTempRoot = if (-not [string]::IsNullOrWhiteSpace([string]$env:RUNNER_TEMP)) { [string]$env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
    $tempXml = Join-Path $taskTempRoot ("managed-task-{0}.xml" -f [guid]::NewGuid().ToString('N'))
    try {
      Set-Content -LiteralPath $tempXml -Value $normalizedXml -Encoding Unicode
      $schtasksArgs = @('/Create','/TN',$taskFullName,'/XML',$tempXml,'/F')
      if ($registrationUser) { $schtasksArgs += @('/RU',$registrationUser) }
      & schtasks.exe @schtasksArgs | Out-Host
      $schtasksExit = $LASTEXITCODE
      if ($schtasksExit -ne 0) {
        throw "Register-ScheduledTask failed: $primaryError ; schtasks fallback failed exit=$schtasksExit"
      }
      $registeredBy = 'schtasks'
      Write-Warning "MANAGED_WINDOWS_TASK_REGISTER_FALLBACK_OK task=$TaskName primary=[$primaryError]"
    } finally {
      Remove-Item -LiteralPath $tempXml -Force -ErrorAction SilentlyContinue
    }
  }

  $global:LASTEXITCODE = 0
  if ($registeredBy -eq 'schtasks') {
    # The ScheduledTasks CIM provider can fail to deserialize/query a perfectly valid task
    # when its source XML came from a machine whose creator account was later renamed.
    # schtasks.exe created the task successfully, so verify through the same scheduler API
    # instead of re-entering the provider that triggered the portability failure.
    & schtasks.exe /Query /TN $taskFullName 2>$null | Out-Null
    $queryExit = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    if ($queryExit -ne 0) { throw "Scheduled task schtasks verification failed: $taskFullName exit=$queryExit" }
    $registered = [pscustomobject]@{
      TaskName=$TaskName
      TaskPath=$TaskPath
      Principal=[pscustomobject]@{ UserId=$registrationUser }
      RegisteredBy='schtasks'
    }
  } else {
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
  }
  Write-Host "MANAGED_WINDOWS_SCHEDULED_TASK_RESTORED path=$TaskPath name=$TaskName registeredBy=$registeredBy"
  return $registered
}
