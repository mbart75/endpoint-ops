BeforeAll {
    Set-StrictMode -Version 3.0

    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:Port   = ([uri]$script:Server.BaseUrl).Port

    $script:Production = '11111111-1111-1111-1111-111111111111'
    $script:Servers   = '22222222-2222-2222-2222-222222222222'

    $script:EventPath = "/EPM/API/Sets/$($script:Production)/Events/Search"
    $script:Log   = "http://localhost:$($script:Port)/EPM/API/_test/requests"

    # The log only retains the NAMES of the keys received, never their values. Counting the calls from a
# route is therefore done by difference, the log being cumulative over the entire duration of the
# server.
    function Measure-EventCall {
        @((Invoke-RestMethod -Uri $script:Log).requests | Where-Object { $_.path -eq $script:EventPath }).Count
    }

    function Get-LastEventCall {
        @((Invoke-RestMethod -Uri $script:Log).requests | Where-Object { $_.path -eq $script:EventPath })[-1]
    }

    $identifiers = [pscredential]::new(
        'mock-epm-user', (ConvertTo-TestSecureString -PlainText 'MOCK-EPM-PASSWORD'))

    Connect-EpmTenant -DispatcherUri "http://localhost:$($script:Port)" -Credential $identifiers | Out-Null
}

AfterAll {
    Disconnect-EpmTenant
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Get-EpmElevationEvent' {

    Context 'Route and pagination' {

        It 'Calls Events/Search by POST' {
            Get-EpmElevationEvent -SetId $script:Production | Out-Null
            (Get-LastEventCall).method | Should -Be 'POST'
        }

        It 'Transmits the filter in the request body rather than the URL' {
            Get-EpmElevationEvent -SetId $script:Production | Out-Null
            (Get-LastEventCall).bodyKeys | Should -Contain 'filter'
        }

        It 'Traverses all three cursor pages' {
            $before = Measure-EventCall
            Get-EpmElevationEvent -SetId $script:Production | Out-Null
            (Measure-EventCall) - $before | Should -Be 3
        }

        It 'Returns all nine events from the set' {
            @(Get-EpmElevationEvent -SetId $script:Production).Count | Should -Be 9
        }

        It 'Returns an empty collection on a set without events' {
            @(Get-EpmElevationEvent -SetId $script:Servers).Count | Should -Be 0
        }
    }

    Context 'Exposed fields' {

        It 'Exposes <_>' -ForEach @(
            'Hash', 'Publisher', 'EventType', 'UserName', 'ComputerName', 'FileName',
            'FilePath', 'FileDescription', 'ProductName', 'Company', 'SourceType',
            'SourceName', 'PolicyName', 'PolicyAction', 'Justification',
            'FirstEventDate', 'LastEventDate', 'UserIsAdmin', 'AgentId') {

            $first = @(Get-EpmElevationEvent -SetId $script:Production)[0]
            $first.PSObject.Properties.Name | Should -Contain $_
        }

        It 'Returns a forty-character hexadecimal SHA-1' {
            # SHA1 and not SHA256: a hash of the wrong length would fool anyone who connected a
# reputation service to it.
            $ev = @(Get-EpmElevationEvent -SetId $script:Production)
            @($ev.Hash | Sort-Object -Unique | Where-Object { $_ -notmatch '^[0-9a-fA-F]{40}$' }).Count |
                Should -Be 0
        }

        It 'Returns five distinct hashes' {
            $ev = @(Get-EpmElevationEvent -SetId $script:Production)
            @($ev.Hash | Sort-Object -Unique).Count | Should -Be 5
        }

        It 'Returns sourceType RemovableDrive for Fabrikam events' {
            $ev = @(Get-EpmElevationEvent -SetId $script:Production | Where-Object Publisher -eq 'Fabrikam Inc')
            @($ev.SourceType | Sort-Object -Unique) | Should -Be @('RemovableDrive')
        }
    }

    Context 'Absent publisher' {

        It 'Returns an empty string rather than $null when Publisher is missing' {
            # A $null here would cause the first report that reads it under Set-StrictMode to be raised, and an
# unknown publisher is information, not a lack of data.
            $withoutPublisher = @(Get-EpmElevationEvent -SetId $script:Production |
                    Where-Object FileName -eq 'tool.exe')
            $withoutPublisher.Count      | Should -Be 1
            $withoutPublisher[0].Publisher | Should -BeExactly ''
        }

        It 'Returns Publisher as a string even when absent' {
            $withoutPublisher = @(Get-EpmElevationEvent -SetId $script:Production |
                    Where-Object FileName -eq 'tool.exe')[0]
            $withoutPublisher.Publisher | Should -BeOfType [string]
        }
    }

    Context 'Dates' {

        It 'Returns FirstEventDate as DateTime, not as a string' {
            $first = @(Get-EpmElevationEvent -SetId $script:Production)[0]
            $first.FirstEventDate | Should -BeOfType [datetime]
        }

        It 'Returns LastEventDate as DateTime, not as a string' {
            $first = @(Get-EpmElevationEvent -SetId $script:Production)[0]
            $first.LastEventDate | Should -BeOfType [datetime]
        }
    }

    Context 'UTC time boundaries' {
        # The introspection log only retains the NAMES of the keys received, never their values: it cannot
# therefore prove that a date was sent in UTC, and extending it to the values would make it the very
# place of the leak it is used to exclude. The proof lies in the BEHAVIOR of the mock server, which
# actually filters on the received boundary and rejects a timestamp without a Z suffix. A date sent
# in local time therefore falls on a different subset, or is refused.

        It 'Rejects a server timestamp that is not in UTC' {
            # This test keeps the assembly itself: without it, the format control of the virtual server could
# disappear without anything signaling it, and the following tests would lose half of their
# detection power.
            $uri   = "http://localhost:$($script:Port)$($script:EventPath)?nextCursor=start"
            $body = '{"filter":"eventDate GE 2026-07-10T08:30:00"}'
            $code  = 0
            try {
                Invoke-RestMethod -Uri $uri -Method Post -Body $body `
                    -Headers @{ Authorization = 'basic MOCK-EPM-TOKEN'; 'Content-Type' = 'application/json' } | Out-Null
            }
            catch { $code = [int]$_.Exception.Response.StatusCode }

            $code | Should -Be 400
        }

        It 'Only retains events after -Since' {
            # 08:30 UTC falls between Alice (08:00Z) and Bob (09:00Z). Issued at local time of a time zone
# offset, the same boundary would move the cutoff and change the count.
            $fromDate = [datetime]::new(2026, 7, 10, 8, 30, 0, [System.DateTimeKind]::Utc)
            @(Get-EpmElevationEvent -SetId $script:Production -Since $fromDate).Count | Should -Be 8
        }

        It 'Excludes from -Since the event before the boundary' {
            $fromDate = [datetime]::new(2026, 7, 10, 8, 30, 0, [System.DateTimeKind]::Utc)
            $ev = @(Get-EpmElevationEvent -SetId $script:Production -Since $fromDate)
            @($ev.UserName) | Should -Not -Contain 'alice'
        }

        It 'Includes the event after the one-hour -Since boundary' {
            $fromDate = [datetime]::new(2026, 7, 10, 8, 30, 0, [System.DateTimeKind]::Utc)
            $ev = @(Get-EpmElevationEvent -SetId $script:Production -Since $fromDate)
            @($ev.UserName) | Should -Contain 'bob'
        }

        It 'Handles a -Since boundary expressed in local time as the same instant' {
            # Same instant, Kind different: the result must be identical. It is the standardization of the Kind
# that is at stake, not the time zone of the test machine.
            $fromDate = [datetime]::new(2026, 7, 10, 8, 30, 0, [System.DateTimeKind]::Utc)
            @(Get-EpmElevationEvent -SetId $script:Production -Since $fromDate.ToLocalTime()).Count |
                Should -Be 8
        }

        It 'Only retains events prior to -Until' {
            $untilDate = [datetime]::new(2026, 7, 22, 14, 30, 0, [System.DateTimeKind]::Utc)
            @(Get-EpmElevationEvent -SetId $script:Production -Until $untilDate).Count | Should -Be 8
        }

        It 'Excludes from -Until the event after the boundary' {
            $untilDate = [datetime]::new(2026, 7, 22, 14, 30, 0, [System.DateTimeKind]::Utc)
            $ev = @(Get-EpmElevationEvent -SetId $script:Production -Until $untilDate)
            @($ev.UserName) | Should -Not -Contain 'henry'
        }

        It 'Combines -Since and -Until on the same query' {
            $fromDate = [datetime]::new(2026, 7, 10, 8, 30, 0, [System.DateTimeKind]::Utc)
            $untilDate = [datetime]::new(2026, 7, 22, 14, 30, 0, [System.DateTimeKind]::Utc)
            @(Get-EpmElevationEvent -SetId $script:Production -Since $fromDate -Until $untilDate).Count |
                Should -Be 7
        }
    }

    Context 'Type of event' {

        It 'Uses the default filter ElevationRequest,ManualRequest' {
            $parameters = (Get-Command Get-EpmElevationEvent).ScriptBlock.Ast.Body.ParamBlock.Parameters
            $type = $parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'EventType' }
            $type.DefaultValue.Extent.Text | Should -Be "'ElevationRequest,ManualRequest'"
        }

        It 'Transmits the request type to the server' {
            # The error read in the declaration does not prove that it is traveling: the mock server filters on
# the received type, only two events are ManualRequests.
            @(Get-EpmElevationEvent -SetId $script:Production -EventType 'ManualRequest').Count |
                Should -Be 2
        }
    }

    Context 'Extraction limit' {
        # The API caps the extraction at 100,000 events per 24 hours. The warning threshold lives in a
# module variable rather than in a literal lost in the middle of the code: this is what allows the
# warning to be proven without creating fifty thousand fixtures, by lowering the threshold for the
# time of a test instead of inflating the data set.

        It 'Keeps 50000 as a warning threshold' {
            InModuleScope EndpointOps { $script:EpmEventWarningThreshold } | Should -Be 50000
        }

        It 'Does not warn on a normal extraction' {
            Get-EpmElevationEvent -SetId $script:Production -WarningVariable quiet -WarningAction SilentlyContinue | Out-Null
            @($quiet).Count | Should -Be 0
        }

        It 'Warns once above the threshold' {
            InModuleScope EndpointOps { $script:EpmEventWarningThreshold = 5 }
            try {
                Get-EpmElevationEvent -SetId $script:Production -WarningVariable noise -WarningAction SilentlyContinue | Out-Null
                @($noise).Count | Should -Be 1
            }
            finally {
                InModuleScope EndpointOps { $script:EpmEventWarningThreshold = 50000 }
            }
        }

        It 'Names the API limit in the warning' {
            # A warning that does not say where the limit comes from sends you to look for the cause in the
# wrong place.
            InModuleScope EndpointOps { $script:EpmEventWarningThreshold = 5 }
            try {
                Get-EpmElevationEvent -SetId $script:Production -WarningVariable noise -WarningAction SilentlyContinue | Out-Null
                @($noise)[0].Message | Should -BeLike '*100,000*'
            }
            finally {
                InModuleScope EndpointOps { $script:EpmEventWarningThreshold = 50000 }
            }
        }

        It 'Does not truncate results when it warns' {
            # A silent truncation would produce a reassuring and false report: this is exactly the failure mode
# to avoid.
            InModuleScope EndpointOps { $script:EpmEventWarningThreshold = 5 }
            try {
                @(Get-EpmElevationEvent -SetId $script:Production -WarningAction SilentlyContinue).Count |
                    Should -Be 9
            }
            finally {
                InModuleScope EndpointOps { $script:EpmEventWarningThreshold = 50000 }
            }
        }
    }
}
