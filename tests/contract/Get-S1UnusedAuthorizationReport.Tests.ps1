BeforeAll {
    Set-StrictMode -Version 3.0

    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
    $script:Server = Start-MockApiServer
    $script:Auth = @{ Authorization = 'ApiToken MOCK-S1-TOKEN' }
    $script:EventPath = '/web/api/v2.1/device-control/events'
    $script:Today = [datetime]'2026-07-24T12:00:00Z'
    Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null

    $script:Params = @{
        PermissiveGroupName = 'grp-permissive'
        RetentionDays       = 90
        AlertAfterDays      = 30
        RemoveAfterDays     = 60
        ReferenceDate       = $script:Today
        ControlSkuAvailable = $true
    }

    function Get-MockMoveLog {
        @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/_test/moves" -Headers $script:Auth).data)
    }
}

AfterAll {
    Disconnect-S1Tenant
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Get-S1UnusedAuthorizationReport' {
    It 'Classifies MOCK-WKS-12 at the removal tier' {
        $finding = Get-S1UnusedAuthorizationReport @script:Params |
            Where-Object ComputerName -eq 'MOCK-WKS-12'

        $finding.State | Should -Be 'NoUsage'
        $finding.Tier | Should -Be 'Removal'
        $finding.Severity | Should -Be 'High'
        $finding.ObservedDays | Should -Be 60
    }

    It 'Classifies MOCK-WKS-11 at the alert tier without proposing a removal' {
        $finding = Get-S1UnusedAuthorizationReport @script:Params |
            Where-Object ComputerName -eq 'MOCK-WKS-11'

        $finding.State | Should -Be 'NoUsage'
        $finding.Tier | Should -Be 'Alert'
        $finding.Tier | Should -Not -Be 'Removal'
        $finding.Severity | Should -Be 'Medium'
        $finding.ObservedDays | Should -Be 30
    }

    It 'emits exactly five Device Control findings for a complete pass' {
        # Front/back offset: the mock server is shared by the entire file.
        $before = Get-MockApiServerHitCount -Server $script:Server -Path $script:EventPath
        Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
            -RetentionDays 90 -AlertAfterDays 30 -RemoveAfterDays 60 `
            -ReferenceDate $script:Today -ControlSkuAvailable | Out-Null
        $after = Get-MockApiServerHitCount -Server $script:Server -Path $script:EventPath

        ($after - $before) | Should -Be 5 -Because 'The removal windows and then the alert windows are counted separately'
    }

    It 'Does not report MOCK-WKS-10 whose use is recent' {
        $names = @(Get-S1UnusedAuthorizationReport @script:Params).ComputerName

        $names | Should -Not -Contain 'MOCK-WKS-10'
    }

    It 'Does not report MOCK-WKS-04 outside of permissive groups' {
        $names = @(Get-S1UnusedAuthorizationReport @script:Params).ComputerName

        $names | Should -Not -Contain 'MOCK-WKS-04'
    }

    It 'MOCK-SRV-10 classifies Linux as OutOfScope rather than NoUsage' {
        $finding = Get-S1UnusedAuthorizationReport @script:Params |
            Where-Object ComputerName -eq 'MOCK-SRV-10'

        $finding.State | Should -Be 'OutOfScope'
        $finding.State | Should -Not -Be 'NoUsage'
        $finding.Tier | Should -Be 'None'
        $finding.Severity | Should -Be 'Low'
    }

    It 'applies the allowlist and classifies MOCK-XXX-10 as OutOfScope' {
        $finding = Get-S1UnusedAuthorizationReport @script:Params |
            Where-Object ComputerName -eq 'MOCK-XXX-10'

        $finding.State | Should -Be 'OutOfScope'
        $finding.State | Should -Not -Be 'NoUsage'
        $finding.Tier | Should -Be 'None'
        $finding.Severity | Should -Be 'Low'
    }

    It 'Degrades to alert when the removal equals the retention' {
        $finding = Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
            -RetentionDays 60 -AlertAfterDays 30 -RemoveAfterDays 60 `
            -ReferenceDate $script:Today -ControlSkuAvailable |
            Where-Object ComputerName -eq 'MOCK-WKS-12'

        $finding.State | Should -Be 'NoUsage'
        $finding.Tier | Should -Be 'Alert'
        $finding.ObservedDays | Should -Be 30
        $finding.Reason | Should -Match 'Removal.*could not be evaluated.*retention'
    }

    It 'Explains that the retention does not cover the requested removal period' {
        $finding = Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
            -RetentionDays 60 -AlertAfterDays 30 -RemoveAfterDays 90 `
            -ReferenceDate $script:Today -ControlSkuAvailable |
            Where-Object ComputerName -eq 'MOCK-WKS-12'

        $finding.State | Should -Be 'NoUsage'
        $finding.Tier | Should -Be 'Alert'
        $finding.ObservedDays | Should -Be 30
        $finding.Reason | Should -Match 'retention.*does not cover.*90-day'
    }

    It 'Exposes the exact schema and clear reasons without a numerical score' {
        $report = @(Get-S1UnusedAuthorizationReport @script:Params)
        $finding = $report | Where-Object ComputerName -eq 'MOCK-WKS-12'

        ($finding.PSObject.Properties.Name -join ',') | Should -Be (
            'ComputerName,AgentId,GroupName,SiteName,State,Tier,Severity,Reason,LastSeenDeviceDate,ObservedDays'
        )
        foreach ($row in $report) {
            $row.Reason | Should -BeOfType [string]
            [string]::IsNullOrWhiteSpace($row.Reason) | Should -BeFalse
            $row.Reason | Should -Not -Match '(?i)\b(?:note|score)\s*[:=]?\s*\d'
        }
    }

    It 'Documents an unrequested date and enriches only when requested' {
        $withoutDate = Get-S1UnusedAuthorizationReport @script:Params |
            Where-Object ComputerName -eq 'MOCK-WKS-11'
        $withDate = Get-S1UnusedAuthorizationReport @script:Params -IncludeLastSeen |
            Where-Object ComputerName -eq 'MOCK-WKS-11'
        $withoutHistory = Get-S1UnusedAuthorizationReport @script:Params -IncludeLastSeen |
            Where-Object ComputerName -eq 'MOCK-WKS-12'

        $withoutDate.GroupName | Should -Be 'grp-permissive'
        $withoutDate.LastSeenDeviceDate | Should -BeNullOrEmpty
        $withoutDate.Reason | Should -Match 'Device Control event.*not requested'
        $withDate.LastSeenDeviceDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') |
            Should -Be '2026-06-14T11:30:00Z'
        $withDate.Reason | Should -Match 'ordering.*not guaranteed'
        $withoutHistory.LastSeenDeviceDate | Should -BeNullOrEmpty
        $withoutHistory.Reason | Should -Match 'No Device Control event date is known'
    }

    It 'Returns no objects on an empty fleet' {
        $accounts = InModuleScope EndpointOps {
            Mock Get-S1Agent { }
            $traversal = 0
            Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
                -RetentionDays 90 -ReferenceDate ([datetime]'2026-07-24T12:00:00Z') `
                -ControlSkuAvailable |
                ForEach-Object { $traversal++ }

            [pscustomobject]@{
                ArrayCount    = @(Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
                    -RetentionDays 90 -ReferenceDate ([datetime]'2026-07-24T12:00:00Z') `
                    -ControlSkuAvailable).Count
                PipelineCount = (Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
                    -RetentionDays 90 -ReferenceDate ([datetime]'2026-07-24T12:00:00Z') `
                    -ControlSkuAvailable |
                    Measure-Object).Count
                ForEachCount  = $traversal
            }
        }

        $accounts.ArrayCount | Should -Be 0
        $accounts.PipelineCount | Should -Be 0
        $accounts.ForEachCount | Should -Be 0
    }

    It 'Issues no write request' {
        $before = @(Get-MockMoveLog).Count
        Get-S1UnusedAuthorizationReport @script:Params | Out-Null
        $after = @(Get-MockMoveLog).Count

        ($after - $before) | Should -Be 0
    }

    It 'Classifies Windows as OutOfScope when SKU availability is unconfirmed and does not query events' {
        $before = Get-MockApiServerHitCount -Server $script:Server -Path $script:EventPath
        $finding = Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
            -RetentionDays 90 -AlertAfterDays 30 -RemoveAfterDays 60 `
            -ReferenceDate $script:Today |
            Where-Object ComputerName -eq 'MOCK-WKS-12'
        $after = Get-MockApiServerHitCount -Server $script:Server -Path $script:EventPath

        $finding.State | Should -Be 'OutOfScope'
        $finding.State | Should -Not -Be 'NoUsage'
        $finding.Tier | Should -Be 'None'
        $finding.Severity | Should -Be 'Low'
        $finding.Reason | Should -Match 'Control SKU.*(?:not confirmed|unavailable)'
        ($after - $before) | Should -Be 0
    }

    It 'Classifies macOS as OutOfScope when SKU availability is unconfirmed and does not query events' {
        $before = Get-MockApiServerHitCount -Server $script:Server -Path $script:EventPath
        $finding = InModuleScope EndpointOps {
            Mock Get-S1Agent {
                [pscustomobject]@{
                    Id           = '2001'
                    ComputerName = 'MOCK-MAC-10'
                    OsType       = 'macos'
                    GroupName    = 'grp-permissive'
                    SiteName     = 'MOCK-SITE-EU'
                }
            }

            Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
                -RetentionDays 90 -AlertAfterDays 30 -RemoveAfterDays 60 `
                -ReferenceDate ([datetime]'2026-07-24T12:00:00Z')
        }
        $after = Get-MockApiServerHitCount -Server $script:Server -Path $script:EventPath

        $finding.State | Should -Be 'OutOfScope'
        $finding.State | Should -Not -Be 'NoUsage'
        $finding.Tier | Should -Be 'None'
        $finding.Severity | Should -Be 'Low'
        $finding.Reason | Should -Match 'Control SKU.*(?:not confirmed|unavailable)'
        ($after - $before) | Should -Be 0
    }

    It 'Does not propose removal when the Control SKU is explicitly unavailable' {
        $report = @(Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
            -RetentionDays 90 -AlertAfterDays 30 -RemoveAfterDays 60 `
            -ReferenceDate $script:Today -ControlSkuAvailable:$false)

        @($report | Where-Object Tier -eq 'Removal').Count | Should -Be 0
        @($report | Where-Object State -eq 'NoUsage').Count | Should -Be 0
    }

    It 'Rejects equal thresholds before any API call' {
        $agentsBefore = Get-MockApiServerHitCount -Server $script:Server -Path '/web/api/v2.1/agents'
        $eventsBefore = Get-MockApiServerHitCount -Server $script:Server -Path $script:EventPath
        $message = ''
        try {
            Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
                -RetentionDays 90 -AlertAfterDays 30 -RemoveAfterDays 30 `
                -ReferenceDate $script:Today | Out-Null
        }
        catch { $message = $_.Exception.Message }
        $agentsAfter = Get-MockApiServerHitCount -Server $script:Server -Path '/web/api/v2.1/agents'
        $eventsAfter = Get-MockApiServerHitCount -Server $script:Server -Path $script:EventPath

        ([pscustomobject]@{
            ClearMessage = $message -match 'AlertAfterDays.*strictly less than.*RemoveAfterDays'
            AgentDelta   = $agentsAfter - $agentsBefore
            EventDelta   = $eventsAfter - $eventsBefore
        } | ConvertTo-Json -Compress) | Should -Be '{"ClearMessage":true,"AgentDelta":0,"EventDelta":0}'
    }

    It 'Rejects inverse thresholds before any API call' {
        $agentsBefore = Get-MockApiServerHitCount -Server $script:Server -Path '/web/api/v2.1/agents'
        $eventsBefore = Get-MockApiServerHitCount -Server $script:Server -Path $script:EventPath
        $message = ''
        try {
            Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
                -RetentionDays 90 -AlertAfterDays 60 -RemoveAfterDays 30 `
                -ReferenceDate $script:Today | Out-Null
        }
        catch { $message = $_.Exception.Message }
        $agentsAfter = Get-MockApiServerHitCount -Server $script:Server -Path '/web/api/v2.1/agents'
        $eventsAfter = Get-MockApiServerHitCount -Server $script:Server -Path $script:EventPath

        ([pscustomobject]@{
            ClearMessage = $message -match 'AlertAfterDays.*strictly less than.*RemoveAfterDays'
            AgentDelta   = $agentsAfter - $agentsBefore
            EventDelta   = $eventsAfter - $eventsBefore
        } | ConvertTo-Json -Compress) | Should -Be '{"ClearMessage":true,"AgentDelta":0,"EventDelta":0}'
    }

    It 'Documents the fail-safe Control SKU guard in the help' {
        $parameter = (Get-Help Get-S1UnusedAuthorizationReport -Full).parameters.parameter |
            Where-Object Name -eq 'ControlSkuAvailable'

        $parameter | Should -Not -BeNullOrEmpty
        ($parameter.description.Text -join ' ') | Should -Match 'Control SKU.*(?:confirmed|evidence)'
    }

    It 'Produces no NoUsage result for a contradictory CountOnly schema' {
        $observation = InModuleScope EndpointOps {
            Mock Get-S1Agent {
                [pscustomobject]@{
                    Id           = '2001'
                    ComputerName = 'MOCK-WKS-CONTRADICTOIRE'
                    OsType       = 'windows'
                    GroupName    = 'grp-permissive'
                    SiteName     = 'MOCK-SITE-EU'
                }
            }
            Mock Invoke-S1Request {
                [pscustomobject]@{
                    data       = [object[]]@([pscustomobject]@{ id = 'evt-contradictoire' })
                    pagination = [pscustomobject]@{ totalItems = 0; nextCursor = $null }
                }
            }

            $report = @()
            $message = ''
            try {
                $report = @(Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-permissive' `
                    -RetentionDays 90 -ReferenceDate ([datetime]'2026-07-24T12:00:00Z') `
                    -ControlSkuAvailable)
            }
            catch { $message = $_.Exception.Message }

            [pscustomobject]@{
                ClearMessage = $message -match 'CountOnly.*data.*empty collection'
                NoUsageCount   = @($report | Where-Object State -eq 'NoUsage').Count
            }
        }

        ($observation | ConvertTo-Json -Compress) |
            Should -Be '{"ClearMessage":true,"NoUsageCount":0}'
    }
}
