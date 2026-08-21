<#
.SYNOPSIS
    Bulk-provisions Active Directory users from a CSV source file.

.DESCRIPTION
    Reads a CSV of new hires, generates a SamAccountName per the
    organization's naming convention (first initial + last name),
    handles collisions, creates the account in the correct department
    OU, assigns a random initial password with forced change at logon,
    and adds the user to their department security group.

.PARAMETER CsvPath
    Path to the source CSV. Required columns:
    FirstName, LastName, Department, Title, Manager

.PARAMETER LogDirectory
    Where transcript logs and the initial credentials file are written.

.EXAMPLE
    .\New-DomlabUser.ps1 -CsvPath ..\data\new-users.csv -WhatIf

.EXAMPLE
    .\New-DomlabUser.ps1 -CsvPath ..\data\new-users.csv

.NOTES
    Author:  Dominique White
    Domain:  DOMLAB.LOCAL
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ })]
    [string]$CsvPath,

    [string]$LogDirectory = "C:\Scripts\ad-automation\logs"
)

Import-Module ActiveDirectory -ErrorAction Stop

# --- Logging setup -------------------------------------------------
if (-not (Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}
$stamp   = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $LogDirectory "provision-$stamp.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logFile -Value $line
    switch ($Level) {
        "ERROR" { Write-Host $line -ForegroundColor Red }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
}

# --- Password generator --------------------------------------------
function New-RandomPassword {
    param([int]$Length = 16)

    # Ambiguous characters (O/0, l/1/I) omitted for readability
    $upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ".ToCharArray()
    $lower   = "abcdefghijkmnpqrstuvwxyz".ToCharArray()
    $digits  = "23456789".ToCharArray()
    $special = "!@#$%^&*-_=+".ToCharArray()

    # Guarantee complexity: one character from each class
    $chars = @(
        $upper   | Get-Random
        $lower   | Get-Random
        $digits  | Get-Random
        $special | Get-Random
    )

    $all = $upper + $lower + $digits + $special
    $chars += (1..($Length - 4) | ForEach-Object { $all | Get-Random })

    # Shuffle so the guaranteed characters aren't always in positions 1-4
    -join ($chars | Sort-Object { Get-Random })
}

# --- Username generator with collision handling --------------------
function New-SamAccountName {
    param([string]$First, [string]$Last)

    # Convention: first initial + last name, lowercase, letters only
    $base = ($First.Substring(0,1) + $Last) -replace '[^a-zA-Z]', ''
    $base = $base.ToLower()

    # SamAccountName has a hard 20-character limit
    if ($base.Length -gt 20) { $base = $base.Substring(0,20) }

    $candidate = $base
    $counter   = 1

    while (Get-ADUser -Filter "SamAccountName -eq '$candidate'" -ErrorAction SilentlyContinue) {
        $suffix    = $counter.ToString()
        $trimTo    = 20 - $suffix.Length
        $candidate = $base.Substring(0, [Math]::Min($base.Length, $trimTo)) + $suffix
        $counter++
        if ($counter -gt 99) {
            throw "Could not generate a unique SamAccountName for $First $Last"
        }
    }

    return $candidate
}

# --- Main -----------------------------------------------------------
Write-Log "=== Provisioning run started ==="
Write-Log "Source CSV: $CsvPath"

$domainDN = (Get-ADDomain).DistinguishedName
$dnsRoot  = (Get-ADDomain).DNSRoot
$baseOU   = "OU=DOMLAB,$domainDN"

$users = Import-Csv -Path $CsvPath
Write-Log "Loaded $($users.Count) records from CSV"

$created = 0
$skipped = 0
$failed  = 0
$results = @()

foreach ($u in $users) {

    # --- Validate required fields ---
    if (-not $u.FirstName -or -not $u.LastName -or -not $u.Department) {
        Write-Log "Skipping record with missing required fields" "WARN"
        $skipped++
        continue
    }

    # --- Verify the target OU exists before attempting creation ---
    $targetOU = "OU=$($u.Department),OU=Users,$baseOU"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$targetOU'" -ErrorAction SilentlyContinue)) {
        Write-Log "Target OU does not exist: $targetOU - skipping $($u.FirstName) $($u.LastName)" "ERROR"
        $failed++
        continue
    }

    try {
        $sam      = New-SamAccountName -First $u.FirstName -Last $u.LastName
        $upn      = "$sam@$dnsRoot"
        $display  = "$($u.FirstName) $($u.LastName)"
        $password = New-RandomPassword
        $secure   = ConvertTo-SecureString $password -AsPlainText -Force

        $params = @{
            Name                  = $display
            GivenName             = $u.FirstName
            Surname               = $u.LastName
            DisplayName           = $display
            SamAccountName        = $sam
            UserPrincipalName     = $upn
            Path                  = $targetOU
            Department            = $u.Department
            Title                 = $u.Title
            AccountPassword       = $secure
            Enabled               = $true
            ChangePasswordAtLogon = $true
            Description           = "Provisioned $(Get-Date -Format 'yyyy-MM-dd') via New-DomlabUser.ps1"
        }

        if ($PSCmdlet.ShouldProcess($display, "Create AD user '$sam' in $($u.Department)")) {

            New-ADUser @params -ErrorAction Stop
            Write-Log "Created user: $sam ($display) in $($u.Department)"

            # --- Department security group ---
            $group = "SEC-$($u.Department)-Users"
            if (Get-ADGroup -Filter "Name -eq '$group'" -ErrorAction SilentlyContinue) {
                Add-ADGroupMember -Identity $group -Members $sam -ErrorAction Stop
                Write-Log "  Added $sam to $group"
            } else {
                Write-Log "  Group $group not found - membership not assigned" "WARN"
            }

            # --- Manager, if specified ---
            if ($u.Manager) {
                if (Get-ADUser -Filter "SamAccountName -eq '$($u.Manager)'" -ErrorAction SilentlyContinue) {
                    Set-ADUser -Identity $sam -Manager $u.Manager -ErrorAction Stop
                    Write-Log "  Set manager to $($u.Manager)"
                } else {
                    Write-Log "  Manager '$($u.Manager)' not found - skipping manager assignment" "WARN"
                }
            }

            $created++
            $results += [PSCustomObject]@{
                DisplayName     = $display
                SamAccountName  = $sam
                UPN             = $upn
                Department      = $u.Department
                InitialPassword = $password
                Status          = "Created"
            }
        }
        else {
            Write-Log "[WHATIF] Would create $sam ($display) in $targetOU"
            $results += [PSCustomObject]@{
                DisplayName     = $display
                SamAccountName  = $sam
                UPN             = $upn
                Department      = $u.Department
                InitialPassword = "(not generated in WhatIf)"
                Status          = "WhatIf"
            }
        }
    }
    catch {
        Write-Log "FAILED to create $($u.FirstName) $($u.LastName): $($_.Exception.Message)" "ERROR"
        $failed++
    }
}

Write-Log "=== Run complete: $created created, $skipped skipped, $failed failed ==="

# --- Credential handoff file ---------------------------------------
if ($created -gt 0) {
    $credFile = Join-Path $LogDirectory "initial-credentials-$stamp.csv"
    $results | Export-Csv -Path $credFile -NoTypeInformation
    Write-Log "Initial credentials written to $credFile - deliver securely and delete."
}

$results | Format-Table -AutoSize