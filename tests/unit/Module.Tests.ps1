BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1'
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module $script:ModulePath -Force -ErrorAction Stop
    $script:Module = Get-Module EndpointOps
}

AfterAll {
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Module EndpointOps' {
    It 'Exposes Get-EndpointOpsVersion' {
        Get-Command -Module 'EndpointOps' -Name 'Get-EndpointOpsVersion' | Should -Not -BeNullOrEmpty
    }

    It 'Exposes the loaded module version rather than 0.0' {
        $v = Get-EndpointOpsVersion
        $v | Should -Not -BeNullOrEmpty
        [version]$v | Should -Be $script:Module.Version
        [version]$v | Should -Not -Be ([version]'0.0')
    }

    It 'Keeps Public files, FunctionsToExport, and exported functions aligned' {
        $publicDir = Join-Path (Split-Path $script:ModulePath) 'Public'
        $fromFiles = @(Get-ChildItem $publicDir -Filter '*.ps1' | ForEach-Object BaseName | Sort-Object)
        $declared  = @((Import-PowerShellDataFile $script:ModulePath).FunctionsToExport | Sort-Object)
        $exported  = @($script:Module.ExportedFunctions.Keys | Sort-Object)

        $declared | Should -Be $fromFiles -Because 'The manifesto must reflect Public/'
        $exported | Should -Be $fromFiles -Because 'The effective export must reflect Public/'
    }

    It 'Defines exactly one matching function in each Public file' {
        $publicDir = Join-Path (Split-Path $script:ModulePath) 'Public'
        foreach ($f in Get-ChildItem $publicDir -Filter '*.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            $fns = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name)
            $fns | Should -Be @($f.BaseName) -Because "$($f.Name) must define the only function $($f.BaseName)"
        }
    }
}
