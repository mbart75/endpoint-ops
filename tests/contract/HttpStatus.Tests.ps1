#Requires -Version 7.6

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
    $script:Server = Start-MockApiServer
    $script:VtKey = ConvertTo-TestSecureString -PlainText 'MOCK-VT-KEY'
}

AfterAll {
    Disconnect-VirusTotal
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Shared HTTP status boundary' {
    It 'Exposes the real status <Status> without retaining a response' -ForEach @(
        @{ Path = '/inexistant'; Status = 404 }
        @{ Path = '/always-fails'; Status = 500 }
    ) {
        $caught = $null
        try { Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)$Path" -MaxAttempts 1 | Out-Null }
        catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception | Should -BeOfType ([System.Net.Http.HttpRequestException])
        [int]$caught.Exception.StatusCode | Should -Be $Status
        $caught.Exception.InnerException | Should -BeNullOrEmpty
        $caught.Exception.Data.Count | Should -Be 0
        $caught.Exception.Message | Should -BeLike "*returned $Status after 1 attempt(s)*"
    }
}

Describe 'VirusTotal typed HTTP decisions' {
    BeforeEach {
        Disconnect-VirusTotal
        Connect-VirusTotal -ApiKey $script:VtKey -BaseUri $script:Server.BaseUrl | Out-Null
    }

    AfterEach { Disconnect-VirusTotal }

    It 'Makes <Attempts> attempts for <Label>, regardless of message text' -ForEach @(
        @{ Label = 'typed 500'; Status = 500; Message = 'No numeric status'; Attempts = 2 }
        @{ Label = 'typed 429'; Status = 429; Message = 'returned 500'; Attempts = 1 }
        @{ Label = 'untyped error'; Status = $null; Message = 'returned 500'; Attempts = 1 }
    ) {
        InModuleScope EndpointOps -Parameters @{ Status = $Status; Message = $Message; Attempts = $Attempts } {
            param($Status, $Message, $Attempts)
            $failure = if ($null -eq $Status) { [System.Exception]::new($Message) }
            else { [System.Net.Http.HttpRequestException]::new($Message, $null, [System.Net.HttpStatusCode]$Status) }
            Mock Invoke-EndpointOpsRequest { throw $failure }
            { Invoke-VtRequest -Path '/api/v3/files/test' -MinIntervalMs 0 } | Should -Throw
            Should -Invoke Invoke-EndpointOpsRequest -Times $Attempts -Exactly
            (Get-VtConnectionState).DailyRequestCount | Should -Be $Attempts
        }
    }

    It 'Classifies <Label> as <Verdict> for both file and URL reports and respects caching' -ForEach @(
        @{ Label = 'typed 400'; Status = 400; Message = 'No numeric status'; Verdict = 'Unknown'; Calls = 1 }
        @{ Label = 'typed 404'; Status = 404; Message = 'returned 500'; Verdict = 'Unknown'; Calls = 1 }
        @{ Label = 'typed 429'; Status = 429; Message = 'returned 404'; Verdict = 'Unavailable'; Calls = 2 }
        @{ Label = 'typed 500'; Status = 500; Message = 'returned 404'; Verdict = 'Unavailable'; Calls = 2 }
        @{ Label = 'untyped error'; Status = $null; Message = 'returned 404'; Verdict = 'Unavailable'; Calls = 2 }
    ) {
        InModuleScope EndpointOps -Parameters @{ Status = $Status; Message = $Message; Verdict = $Verdict; Calls = $Calls } {
            param($Status, $Message, $Verdict, $Calls)
            $failure = if ($null -eq $Status) { [System.Exception]::new($Message) }
            else { [System.Net.Http.HttpRequestException]::new($Message, $null, [System.Net.HttpStatusCode]$Status) }
            Mock Invoke-VtRequest { throw $failure }
            $hash = ('A' * 38) + '01'
            $url = 'https://unknown.example.invalid/?aa'
            $reports = @(
                Get-VtFileReport -Hash $hash -MinIntervalMs 0
                Get-VtFileReport -Hash $hash -MinIntervalMs 0
                Get-VtUrlReport -Url $url -MinIntervalMs 0
                Get-VtUrlReport -Url $url -MinIntervalMs 0
            )
            $reports.Count | Should -Be 4
            foreach ($report in $reports) { $report.Verdict | Should -BeExactly $Verdict }
            Should -Invoke Invoke-VtRequest -Times $Calls -Exactly -ParameterFilter { $Path -like '/api/v3/files/*' }
            Should -Invoke Invoke-VtRequest -Times $Calls -Exactly -ParameterFilter { $Path -like '/api/v3/urls/*' }
        }
    }
}
