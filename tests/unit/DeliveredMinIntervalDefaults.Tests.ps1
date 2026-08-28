BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1'
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module $script:ModulePath -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'VirusTotal interval defaults' {
    It 'Get-VtFileReport returns ValidateRange, int and 15000 ms by default' {
        $command = Get-Command -Name 'Get-VtFileReport' -Module 'EndpointOps' -CommandType Function
        $parameter = @($command.ScriptBlock.Ast.Body.ParamBlock.Parameters |
                Where-Object { $_.Name.VariablePath.UserPath -eq 'MinIntervalMs' })
        $range = @($parameter.Attributes |
                Where-Object { $_.TypeName.FullName -eq 'ValidateRange' })

        $parameter.Count | Should -Be 1
        $parameter.StaticType.FullName | Should -Be 'System.Int32'
        $parameter.DefaultValue.Extent.Text | Should -Be '15000'
        $range.Count | Should -Be 1
        $range.PositionalArguments[0].Extent.Text | Should -Be '0'
        $range.PositionalArguments[1].Extent.Text | Should -Be '600000'
    }

    It 'Get-VtUrlReport returns ValidateRange, int and 15000 ms by default' {
        $command = Get-Command -Name 'Get-VtUrlReport' -Module 'EndpointOps' -CommandType Function
        $parameter = @($command.ScriptBlock.Ast.Body.ParamBlock.Parameters |
                Where-Object { $_.Name.VariablePath.UserPath -eq 'MinIntervalMs' })
        $range = @($parameter.Attributes |
                Where-Object { $_.TypeName.FullName -eq 'ValidateRange' })

        $parameter.Count | Should -Be 1
        $parameter.StaticType.FullName | Should -Be 'System.Int32'
        $parameter.DefaultValue.Extent.Text | Should -Be '15000'
        $range.Count | Should -Be 1
        $range.PositionalArguments[0].Extent.Text | Should -Be '0'
        $range.PositionalArguments[1].Extent.Text | Should -Be '600000'
    }

    It 'Get-EpmElevationSummary uses ValidateRange, int and 15000 ms by default' {
        $command = Get-Command -Name 'Get-EpmElevationSummary' -Module 'EndpointOps' -CommandType Function
        $parameter = @($command.ScriptBlock.Ast.Body.ParamBlock.Parameters |
                Where-Object { $_.Name.VariablePath.UserPath -eq 'MinIntervalMs' })
        $range = @($parameter.Attributes |
                Where-Object { $_.TypeName.FullName -eq 'ValidateRange' })

        $parameter.Count | Should -Be 1
        $parameter.StaticType.FullName | Should -Be 'System.Int32'
        $parameter.DefaultValue.Extent.Text | Should -Be '15000'
        $range.Count | Should -Be 1
        $range.PositionalArguments[0].Extent.Text | Should -Be '0'
        $range.PositionalArguments[1].Extent.Text | Should -Be '600000'
    }
}
