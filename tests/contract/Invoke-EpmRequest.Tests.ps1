BeforeAll {
    Set-StrictMode -Version 3.0

    function Get-EpmRequestLog {
        <#
        .SYNOPSIS
            Reads mock EPM requests recorded after a given index.
        .DESCRIPTION
            Each test captures the current request count before exercising the system, then reads
            only the requests it produced. This keeps pagination assertions independent of test
            execution order.
        #>
        [CmdletBinding()]
        param([int]$Since = 0)

        $log = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/EPM/API/_test/requests").requests)
        if ($Since -ge $log.Count) { return @() }
        return @($log[$Since..($log.Count - 1)])
    }

    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    # Dot-sourcing places the synthetic connection state in the same scope as the private request
    # helpers. This isolates Invoke-EpmRequest and avoids exercising the public authentication flow
    # in tests focused on transport and pagination behavior.
    $root = Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps'
    . (Join-Path $root 'Private' 'Get-PropertyOrDefault.ps1')
    . (Join-Path $root 'Private' 'Invoke-EndpointOpsHttpRequest.ps1')
    . (Join-Path $root 'Public'  'Invoke-EndpointOpsRequest.ps1')
    . (Join-Path $root 'Private' 'Get-EpmNextCursor.ps1')
    . (Join-Path $root 'Private' 'Get-EpmConnectionState.ps1')
    . (Join-Path $root 'Private' 'Invoke-EpmRequest.ps1')

    $script:Server = Start-MockApiServer

    # The two URLs deliberately differ, and DispatcherUri is unreachable. Any request built from
    # DispatcherUri instead of ManagerUri therefore fails immediately and unambiguously.
    $script:EpmConnection = [pscustomobject]@{
        DispatcherUri = 'http://localhost:9/EPM/API/Auth/EPM/Logon'
        ManagerUri    = $script:Server.BaseUrl
        Token         = ConvertTo-TestSecureString -PlainText 'MOCK-EPM-TOKEN'
        ConnectedAt   = Get-Date
    }
}

AfterAll {
    $script:EpmConnection = $null
    Stop-MockApiServer -Server $script:Server
}

Describe 'Invoke-EpmRequest' {

    Context 'Simple call' {

        It 'Returns the deserialized object from a GET' {
            $response = Invoke-EpmRequest -Path '/EPM/API/Sets'
            $response.PSObject.Properties.Name | Should -Contain 'SetsCount'
        }

        # Avoid angle-bracket placeholders in the title because Pester treats them as data-template variables.
        It 'Sends exactly the lowercase "basic" scheme followed by the raw token' {
            # The mock compares the header case-sensitively and records only a boolean result, never the token.
            $index = @(Get-EpmRequestLog).Count
            Invoke-EpmRequest -Path '/EPM/API/Sets' | Out-Null

            $calls = @(Get-EpmRequestLog -Since $index | Where-Object { $_.path -eq '/EPM/API/Sets' })
            $calls.Count | Should -Be 1
            $calls[0].authExact | Should -BeTrue
        }

        It 'Builds the URL on ManagerUri, never on DispatcherUri' {
            # DispatcherUri is unreachable. A recorded mock request therefore proves that ManagerUri was used.
            $index = @(Get-EpmRequestLog).Count
            Invoke-EpmRequest -Path '/EPM/API/Sets' | Out-Null

            $calls = @(Get-EpmRequestLog -Since $index | Where-Object { $_.path -eq '/EPM/API/Sets' })
            $calls.Count | Should -Be 1
        }
    }

    Context 'Pagination by offset' {

        It 'Traverses the three pages and concatenates the elements' {
            $items = @(Invoke-EpmRequest -Path '/EPM/API/_test/offset-pages' -PaginationStyle Offset -Limit 2)
            $items.Count | Should -Be 5
            @($items.id) | Should -Be @('ep-1', 'ep-2', 'ep-3', 'ep-4', 'ep-5')
        }

        It 'Emits offsets that are all multiples of limit' {
            # The middle page is partial. Advancing by the received item count would incorrectly request
            # offset=3; advancing by limit produces the expected sequence.
            $index = @(Get-EpmRequestLog).Count
            Invoke-EpmRequest -Path '/EPM/API/_test/offset-pages' -PaginationStyle Offset -Limit 2 | Out-Null

            $calls = @(Get-EpmRequestLog -Since $index | Where-Object { $_.path -eq '/EPM/API/_test/offset-pages' })
            @($calls | ForEach-Object { $_.query.offset }) | Should -Be @('0', '2', '4')
        }

        It 'Ends on an empty page when the response does not have a TotalCount' {
            # TotalCount is not guaranteed on every offset-paginated route, and the documentation does not
            # define one universal list-response shape. On a route that omits it, the empty page is the only
            # stopping condition; without this test, that behavior would never be exercised.
            #
            # MaxPages is deliberately small: if the stop on an empty page was broken, the path
            # would go to the limit. Bounding here fails quickly instead of grinding on.
            $items = @(Invoke-EpmRequest -Path '/EPM/API/_test/offset-no-total' `
                    -PaginationStyle Offset -Limit 2 -MaxPages 6)
            @($items.id) | Should -Be @('et-1', 'et-2', 'et-3')
        }
    }

    Context 'Pagination by cursor' {

        It 'Emits "start" on the first page and then the returned value' {
            $index = @(Get-EpmRequestLog).Count
            Invoke-EpmRequest -Path '/EPM/API/_test/cursor-pages-empty' -PaginationStyle Cursor -Limit 2 | Out-Null

            $calls = @(Get-EpmRequestLog -Since $index | Where-Object { $_.path -eq '/EPM/API/_test/cursor-pages-empty' })
            @($calls | ForEach-Object { $_.query.nextCursor }) | Should -Be @('start', 'Page 2 of the document', 'Page 3')
        }

        It 'Stops pagination when the end cursor is an empty string' {
            $items = @(Invoke-EpmRequest -Path '/EPM/API/_test/cursor-pages-empty' -PaginationStyle Cursor -Limit 2)
            @($items.id) | Should -Be @('ec-1', 'ec-2', 'ec-3', 'ec-4', 'ec-5')
        }

        It 'Stops pagination on a null end cursor' {
            # This is the second end-of-pagination representation shown by the documentation example, which
            # contradicts the accompanying text. Keeping this test separate prevents a failure in the previous
            # assertion from masking this case.
            $items = @(Invoke-EpmRequest -Path '/EPM/API/_test/cursor-pages-null' -PaginationStyle Cursor -Limit 2)
            @($items.id) | Should -Be @('en-1', 'en-2', 'en-3')
        }
    }

    Context 'Request body' {

        It 'Transmits the body to every page, not only the first' {
            # Omitting the body after page one would silently return unfiltered results on later pages.
            $index = @(Get-EpmRequestLog).Count
            Invoke-EpmRequest -Path '/EPM/API/_test/cursor-pages-empty' -Method 'Post' `
                -Body '{"filter":"eventType IN ElevationRequest"}' -PaginationStyle Cursor -Limit 2 | Out-Null

            $calls = @(Get-EpmRequestLog -Since $index |
                Where-Object { $_.path -eq '/EPM/API/_test/cursor-pages-empty' -and $_.method -eq 'POST' })
            $calls.Count | Should -Be 3
            @($calls | ForEach-Object { @($_.bodyKeys) -contains 'filter' }) | Should -Be @($true, $true, $true)
        }
    }

    Context 'Pagination guards' {
        # These guards bound malformed server pagination and must fail with a diagnostic cause.

        It 'Throws when the page limit is reached' {
            # The error must name the limit so operators can diagnose and adjust it without reading source.
            { Invoke-EpmRequest -Path '/EPM/API/_test/cursor-runaway' -PaginationStyle Cursor -Limit 2 -MaxPages 3 } |
                Should -Throw -ExpectedMessage '*3 page limit*'
        }

        It 'Does not emit more pages than the limit' {
            # Verify that the guard stops before issuing a request beyond the configured limit.
            $index = @(Get-EpmRequestLog).Count
            try { Invoke-EpmRequest -Path '/EPM/API/_test/cursor-runaway' -PaginationStyle Cursor -Limit 2 -MaxPages 3 }
            catch { $null = $_ }

            $calls = @(Get-EpmRequestLog -Since $index | Where-Object { $_.path -eq '/EPM/API/_test/cursor-runaway' })
            $calls.Count | Should -Be 3
        }

        It 'Throws when a cursor repeats' {
            # Keep MaxPages high so only the repeated-cursor guard can satisfy this test.
            { Invoke-EpmRequest -Path '/EPM/API/_test/cursor-repeat' -PaginationStyle Cursor -Limit 2 -MaxPages 10 } |
                Should -Throw -ExpectedMessage '*EPM cursor repeats*'
        }

        It 'Detects a repeated cursor before reaching the limit' {
            # Confirm that repeated-cursor detection triggers before the page limit.
            $index = @(Get-EpmRequestLog).Count
            try { Invoke-EpmRequest -Path '/EPM/API/_test/cursor-repeat' -PaginationStyle Cursor -Limit 2 -MaxPages 10 }
            catch { $null = $_ }

            $calls = @(Get-EpmRequestLog -Since $index | Where-Object { $_.path -eq '/EPM/API/_test/cursor-repeat' })
            $calls.Count | Should -Be 2
        }
    }

    Context 'Expired session' {

        It 'Throws an error indicating that the session has expired' {
            { Invoke-EpmRequest -Path '/EPM/API/_test/expired' } |
                Should -Throw -ExpectedMessage '*session*expire*'
        }

        It 'Warns about the one-minute delay while instructing the user to reconnect' {
            # The warning explains the one-minute authentication interval before asking the user to reconnect.
            $message = ''
            try { Invoke-EpmRequest -Path '/EPM/API/_test/expired' }
            catch { $message = $_.Exception.Message }

            $message | Should -BeLike '*Connect-EpmTenant*'
            $message | Should -BeLike '*one connection per minute*' `
                -Because 'The warning must accompany the instruction, not follow it in another message'
        }

        It 'Does not put the token in the error message' {
            # A token copied into an error message could be exposed in CI logs.
            $message = ''
            try { Invoke-EpmRequest -Path '/EPM/API/_test/expired' }
            catch { $message = $_.Exception.Message }

            $message | Should -Not -BeNullOrEmpty
            $message | Should -Not -BeLike '*MOCK-EPM-TOKEN*'
        }
    }
}
