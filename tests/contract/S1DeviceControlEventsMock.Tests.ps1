BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    $script:Server = Start-MockApiServer
    $script:Auth   = @{ Authorization = 'ApiToken MOCK-S1-TOKEN' }
    $script:Path   = '/web/api/v2.1/device-control/events'
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
}

Describe 'Mock server - Device Control events' {
    It 'Rejects the route without a SentinelOne token' {
        $r = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$script:Path" -SkipHttpErrorCheck

        $r.StatusCode | Should -Be 401
    }

    It 'Returns events in data with a pagination cursor' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)$script:Path" -Headers $script:Auth

        $r.data.Count | Should -Be 1
        $r.pagination.totalItems | Should -Be 2
        $r.pagination.nextCursor | Should -Not -BeNullOrEmpty
    }

    It 'Filters events by agentIds' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)$($script:Path)?agentIds=1007" -Headers $script:Auth

        $r.pagination.totalItems | Should -Be 1
        $r.data.agentId | Should -Be '1007'
    }

    It 'Filters eventTime__gte in UTC' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)$($script:Path)?eventTime__gte=2026-07-01T00:00:00Z" -Headers $script:Auth

        $r.pagination.totalItems | Should -Be 1
        $r.data.agentId | Should -Be '1006'
    }

    It 'Rejects eventTime__gte when the time is not exact UTC' {
        $r = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:Path)?eventTime__gte=2026-07-19" `
            -Headers $script:Auth -SkipHttpErrorCheck

        $r.StatusCode | Should -Be 400
    }

    It 'Rejects eventTime__gte when the boundary has an explicit offset' {
        $r = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:Path)?eventTime__gte=2026-07-19T11:00:00%2B02:00" `
            -Headers $script:Auth -SkipHttpErrorCheck

        $r.StatusCode | Should -Be 400
    }

    It 'Returns the count without objects when countOnly is true' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)$($script:Path)?countOnly=true" -Headers $script:Auth

        $r.data.Count | Should -Be 0
        $r.pagination.totalItems | Should -Be 2
    }

    It 'Filters events by groupIds' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)$($script:Path)?groupIds=grp-permissive" -Headers $script:Auth

        $r.pagination.totalItems | Should -Be 2
        $r.data.groupId | Should -Be 'grp-permissive'
    }

    It 'Rejects invalid input without stopping the listener' -TestCases @(
        @{ Query = 'eventTime__gte=2026-99-99T99:99:99Z' }
        @{ Query = 'cursor=events-2147483648' }
        @{ Query = 'limit=1001' }
    ) {
        param($Query)

        $invalid = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:Path)?$Query" `
            -Headers $script:Auth -SkipHttpErrorCheck
        $invalid.StatusCode | Should -Be 400

        $valid = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)$script:Path" -Headers $script:Auth
        $valid.pagination.totalItems | Should -Be 2
    }
}
