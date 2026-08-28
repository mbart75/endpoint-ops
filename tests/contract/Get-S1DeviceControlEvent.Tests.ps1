BeforeAll {
    Set-StrictMode -Version 3.0

    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
    $script:Server = Start-MockApiServer
    Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
    $script:Path = '/web/api/v2.1/device-control/events'
}

AfterAll {
    Disconnect-S1Tenant
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Get-S1DeviceControlEvent' {
    It 'Follows the cursor and returns all fixture events' {
        $events = @(Get-S1DeviceControlEvent)

        $events.Count | Should -Be 2
        @($events.Id | Sort-Object) | Should -Be @('evt-1006-01', 'evt-1007-01')
    }

    It 'Applies -Limit to the first page in one call' {
        # Two elements prove that Limit is transmitted to the server: its default page size is one,
# even without pagination.
        @(Get-S1DeviceControlEvent -Limit 2).Count | Should -Be 2

        $before = Get-MockApiServerHitCount -Server $script:Server -Path $script:Path
        $events = @(Get-S1DeviceControlEvent -Limit 1)
        $after = Get-MockApiServerHitCount -Server $script:Server -Path $script:Path

        ($after - $before) | Should -Be 1
        $events.Count | Should -Be 1
        $events[0].Id | Should -Be 'evt-1006-01'
        $events[0].AgentId | Should -Be '1006'
        $events[0].GroupId | Should -Be 'grp-permissive'
        $events[0].SiteId | Should -Be 'MOCK-SITE-EU'
        $events[0].EventTime | Should -BeOfType [datetime]
        $events[0].EventTime.Kind | Should -Be ([datetimekind]::Utc)
    }

    It 'Transmits -AgentId in the request query' {
        # The mock filter intercepts real HTTP calls. Two events exist, but only the one at 1007 must
# survive the filter sent by the command.
        $events = @(Get-S1DeviceControlEvent -AgentId '1007')

        $events.Count | Should -Be 1
        $events[0].AgentId | Should -Be '1007'
    }

    It 'Normalizes local -Since to ISO-8601 UTC boundary' {
        # The mock explicitly rejects an ISO timestamp with an offset. This local date represents the same
# instant as 2026-07-01T00:00:00Z.
        $since = [datetime]::new(2026, 7, 1, 0, 0, 0, [datetimekind]::Utc).ToLocalTime()

        $events = @(Get-S1DeviceControlEvent -Since $since)

        $events.Count | Should -Be 1
        $events[0].AgentId | Should -Be '1006'
    }

    It 'Returns an integer for -CountOnly' {
        $count = Get-S1DeviceControlEvent -CountOnly

        $count | Should -BeOfType [int]
        $count | Should -Be 2
    }

    It 'Sends exactly one non-paginated request for -CountOnly' {
        # The counter is cumulative over the duration of the shared server by this file: only the difference
# before/after proves this contract.
        $before = Get-MockApiServerHitCount -Server $script:Server -Path $script:Path
        Get-S1DeviceControlEvent -CountOnly | Out-Null
        $after = Get-MockApiServerHitCount -Server $script:Server -Path $script:Path

        ($after - $before) | Should -Be 1 -Because 'CountOnly avoids the page navigation'
    }

    It 'Rejects -Limit with -CountOnly before any HTTP call' {
        $before = Get-MockApiServerHitCount -Server $script:Server -Path $script:Path
        $message = ''
        try {
            Get-S1DeviceControlEvent -Limit 1 -CountOnly | Out-Null
        }
        catch { $message = $_.Exception.Message }
        $after = Get-MockApiServerHitCount -Server $script:Server -Path $script:Path

        $message | Should -Match 'Limit.*CountOnly.*cannot be used together'
        ($after - $before) | Should -Be 0
    }

    It 'Exposes all normalized fields, with EventTime UTC' {
        $deviceEvent = @(Get-S1DeviceControlEvent)[0]

        $deviceEvent.PSObject.TypeNames | Should -Contain 'EndpointOps.S1.DeviceControlEvent'
        $deviceEvent.PSObject.Properties.Name | Should -Contain 'Id'
        $deviceEvent.PSObject.Properties.Name | Should -Contain 'AgentId'
        $deviceEvent.PSObject.Properties.Name | Should -Contain 'GroupId'
        $deviceEvent.PSObject.Properties.Name | Should -Contain 'SiteId'
        $deviceEvent.PSObject.Properties.Name | Should -Contain 'EventTime'
        $deviceEvent.EventTime | Should -BeOfType [datetime]
        $deviceEvent.EventTime.Kind | Should -Be ([datetimekind]::Utc)
    }

    It 'Returns no objects when there are no events' {
        $events = @(Get-S1DeviceControlEvent -AgentId '9999')
        $traversal = 0
        Get-S1DeviceControlEvent -AgentId '9999' | ForEach-Object { $traversal++ }

        $events.Count | Should -Be 0
        (Get-S1DeviceControlEvent -AgentId '9999' | Measure-Object).Count | Should -Be 0
        $traversal | Should -Be 0
    }

    It 'Rejects an absent or invalid CountOnly schema' -ForEach @(
        @{ Case = 'Absent pagination'; Response = [pscustomobject]@{} }
        @{ Case = 'totalItems absent'; Response = [pscustomobject]@{ pagination = [pscustomobject]@{} } }
        @{ Case = 'Null totalItems'; Response = [pscustomobject]@{ pagination = [pscustomobject]@{ totalItems = $null } } }
        @{ Case = 'Negative totalItems'; Response = [pscustomobject]@{ pagination = [pscustomobject]@{ totalItems = -1 } } }
        @{ Case = 'Total non-numeric items'; Response = [pscustomobject]@{ pagination = [pscustomobject]@{ totalItems = 'many' } } }
    ) {
        param($Case, $Response)

        $message = InModuleScope EndpointOps -Parameters @{ RawResponse = $Response } {
            param($RawResponse)
            $script:CountOnlyMalformedResponse = $RawResponse
            Mock Invoke-S1Request { $script:CountOnlyMalformedResponse }

            try {
                Get-S1DeviceControlEvent -CountOnly | Out-Null
                ''
            }
            catch { $_.Exception.Message }
            finally {
                Remove-Variable -Name CountOnlyMalformedResponse -Scope Script -ErrorAction SilentlyContinue
            }
        }

        $message | Should -Match 'CountOnly.*pagination.totalItems.*non-negative integer' -Because $Case
    }

    It 'Rejects a CountOnly schema with non-empty data despite a zero count' {
        $message = InModuleScope EndpointOps {
            Mock Invoke-S1Request {
                [pscustomobject]@{
                    data       = [object[]]@([pscustomobject]@{ id = 'evt-contradictoire' })
                    pagination = [pscustomobject]@{ totalItems = 0; nextCursor = $null }
                }
            }

            try {
                Get-S1DeviceControlEvent -CountOnly | Out-Null
                ''
            }
            catch { $_.Exception.Message }
        }

        $message | Should -Match 'CountOnly.*data.*empty collection'
    }

    It 'Rejects a CountOnly schema with a non-empty nextCursor' {
        $message = InModuleScope EndpointOps {
            Mock Invoke-S1Request {
                [pscustomobject]@{
                    data       = [object[]]@()
                    pagination = [pscustomobject]@{ totalItems = 0; nextCursor = 'cursor-contradictoire' }
                }
            }

            try {
                Get-S1DeviceControlEvent -CountOnly | Out-Null
                ''
            }
            catch { $_.Exception.Message }
        }

        $message | Should -Match 'CountOnly.*pagination.nextCursor.*absent.*null.*empty'
    }

    It 'Rejects a missing or invalid limited-response schema' -ForEach @(
        @{ Case = 'Missing data'; Response = [pscustomobject]@{} }
        @{ Case = 'Null data'; Response = [pscustomobject]@{ data = $null } }
        @{ Case = 'Data string'; Response = [pscustomobject]@{ data = 'evt' } }
        @{ Case = 'Scalar data'; Response = [pscustomobject]@{ data = 42 } }
        @{ Case = 'Non-collection data object'; Response = [pscustomobject]@{ data = [pscustomobject]@{ id = 'evt' } } }
        @{ Case = 'Null element'; Response = [pscustomobject]@{ data = [object[]]@($null) } }
        @{ Case = 'Primitive element'; Response = [pscustomobject]@{ data = [object[]]@('evt') } }
        @{ Case = 'Element nested table'; Response = ('{"data":[[{"id":"evt"}]]}' | ConvertFrom-Json) }
        @{ Case = 'Element dictionary'; Response = [pscustomobject]@{ data = [object[]]@(@{ id = 'evt' }) } }
        @{ Case = 'Other type reference element'; Response = [pscustomobject]@{ data = [object[]]@([System.Text.StringBuilder]::new('evt')) } }
    ) {
        param($Case, $Response)

        $message = InModuleScope EndpointOps -Parameters @{ RawResponse = $Response } {
            param($RawResponse)
            $script:LimitedMalformedResponse = $RawResponse
            Mock Invoke-S1Request { $script:LimitedMalformedResponse }

            try {
                Get-S1DeviceControlEvent -Limit 1 | Out-Null
                ''
            }
            catch { $_.Exception.Message }
            finally {
                Remove-Variable -Name LimitedMalformedResponse -Scope Script -ErrorAction SilentlyContinue
            }
        }

        $message | Should -Match '(?i)limited query.*data.*collection.*non-null.*objects' -Because $Case
    }

    It 'Returns no objects when data is an empty array' {
        $counts = InModuleScope EndpointOps {
            Mock Invoke-S1Request { [pscustomobject]@{ data = [object[]]@() } }

            [pscustomobject]@{
                ArrayCount    = @(Get-S1DeviceControlEvent -Limit 1).Count
                PipelineCount = (Get-S1DeviceControlEvent -Limit 1 | Measure-Object).Count
            }
        }

        $counts.ArrayCount | Should -Be 0
        $counts.PipelineCount | Should -Be 0
    }

    It 'Rejects an AgentId consisting only of spaces before any HTTP call' {
        $before = Get-MockApiServerHitCount -Server $script:Server -Path $script:Path
        $caughtError = $null
        try {
            Get-S1DeviceControlEvent -AgentId '   ' | Out-Null
        }
        catch { $caughtError = $_ }
        $after = Get-MockApiServerHitCount -Server $script:Server -Path $script:Path

        ($null -ne $caughtError) | Should -BeTrue
        $caughtError.Exception | Should -BeOfType [System.Management.Automation.ParameterBindingException]
        ($after - $before) | Should -Be 0
    }
}
