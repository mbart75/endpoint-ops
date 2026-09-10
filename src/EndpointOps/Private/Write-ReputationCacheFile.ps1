function Write-ReputationCacheFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CachePath,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries
    )

    $temporaryStem = "$CachePath.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    $temporaryPath = $temporaryStem
    $temporaryDirectory = $null
    $stream = $null
    $writer = $null
    try {
        $json = ConvertTo-Json -InputObject $Entries -Depth 4 -ErrorAction Stop

        $isWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows)
        $unixModeProperty = [System.IO.FileStreamOptions].GetProperty('UnixCreateMode')
        if (-not $isWindowsPlatform -and $null -ne $unixModeProperty) {
            $ownerReadWrite = [System.IO.UnixFileMode]::UserRead -bor
                [System.IO.UnixFileMode]::UserWrite
            $temporaryCreateMode = $ownerReadWrite
            if ([System.IO.File]::Exists($CachePath)) {
                $destinationMode = [System.IO.File]::GetUnixFileMode($CachePath)
                $publicBits = [System.IO.UnixFileMode]::GroupRead -bor
                    [System.IO.UnixFileMode]::GroupWrite -bor
                    [System.IO.UnixFileMode]::GroupExecute -bor
                    [System.IO.UnixFileMode]::OtherRead -bor
                    [System.IO.UnixFileMode]::OtherWrite -bor
                    [System.IO.UnixFileMode]::OtherExecute
                if (($destinationMode -band $publicBits) -eq [System.IO.UnixFileMode]::None) {
                    $temporaryCreateMode = $destinationMode
                }
            }
            $options = [System.IO.FileStreamOptions]::new()
            $options.Mode = [System.IO.FileMode]::CreateNew
            $options.Access = [System.IO.FileAccess]::ReadWrite
            $options.Share = [System.IO.FileShare]::None
            $options.UnixCreateMode = $temporaryCreateMode
            $stream = [System.IO.FileStream]::new($temporaryPath, $options)
        }
        else {
            # PowerShell 7.2 uses .NET 6, before UnixCreateMode was available. A private sibling
            # directory prevents an empty, briefly inherited file from being opened before its
            # permissions are restricted. No cache content is written until the file is private.
            $temporaryDirectory = $temporaryStem
            [System.IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
            if ($isWindowsPlatform) {
                $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                $directorySecurity = [System.Security.AccessControl.DirectorySecurity]::new()
                $directorySecurity.SetAccessRuleProtection($true, $false)
                $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $directoryRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $identity,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    $inheritance,
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow)
                $directorySecurity.AddAccessRule($directoryRule)
                [System.IO.FileSystemAclExtensions]::SetAccessControl(
                    [System.IO.DirectoryInfo]::new($temporaryDirectory), $directorySecurity)
            }
            else {
                $chmodInfo = [System.Diagnostics.ProcessStartInfo]::new()
                $chmodInfo.FileName = 'chmod'
                $chmodInfo.UseShellExecute = $false
                $null = $chmodInfo.ArgumentList.Add('700')
                $null = $chmodInfo.ArgumentList.Add($temporaryDirectory)
                $chmod = [System.Diagnostics.Process]::Start($chmodInfo)
                $chmod.WaitForExit()
                $chmodExitCode = $chmod.ExitCode
                $chmod.Dispose()
                if ($chmodExitCode -ne 0) {
                    throw 'EndpointOps: could not secure the reputation cache staging directory.'
                }
            }

            $temporaryPath = Join-Path $temporaryDirectory 'cache'
            $stream = [System.IO.FileStream]::new(
                $temporaryPath,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None)
            if ($isWindowsPlatform) {
                if ([System.IO.File]::Exists($CachePath)) {
                    $destinationSecurity = [System.IO.FileSystemAclExtensions]::GetAccessControl(
                        [System.IO.FileInfo]::new($CachePath))
                    [System.IO.FileSystemAclExtensions]::SetAccessControl($stream, $destinationSecurity)
                }
                else {
                    $fileSecurity = [System.Security.AccessControl.FileSecurity]::new()
                    $fileSecurity.SetAccessRuleProtection($true, $false)
                    $fileRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                        $identity,
                        [System.Security.AccessControl.FileSystemRights]::FullControl,
                        [System.Security.AccessControl.AccessControlType]::Allow)
                    $fileSecurity.AddAccessRule($fileRule)
                    [System.IO.FileSystemAclExtensions]::SetAccessControl($stream, $fileSecurity)
                }
            }
            else {
                $temporaryMode = '600'
                if ([System.IO.File]::Exists($CachePath)) {
                    $statInfo = [System.Diagnostics.ProcessStartInfo]::new()
                    $statInfo.FileName = 'stat'
                    $statInfo.UseShellExecute = $false
                    $statInfo.RedirectStandardOutput = $true
                    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
                            [System.Runtime.InteropServices.OSPlatform]::OSX)) {
                        $null = $statInfo.ArgumentList.Add('-f')
                        $null = $statInfo.ArgumentList.Add('%Lp')
                    }
                    else {
                        $null = $statInfo.ArgumentList.Add('-c')
                        $null = $statInfo.ArgumentList.Add('%a')
                    }
                    $null = $statInfo.ArgumentList.Add($CachePath)
                    $stat = [System.Diagnostics.Process]::Start($statInfo)
                    $statOutput = $stat.StandardOutput.ReadToEnd().Trim()
                    $stat.WaitForExit()
                    $statExitCode = $stat.ExitCode
                    $stat.Dispose()
                    if ($statExitCode -ne 0) {
                        throw 'EndpointOps: could not inspect existing reputation cache permissions.'
                    }
                    try { $modeValue = [Convert]::ToInt32($statOutput, 8) }
                    catch [System.FormatException] {
                        throw 'EndpointOps: existing reputation cache permissions are invalid.'
                    }
                    if (($modeValue -band 63) -eq 0) {
                        $temporaryMode = [Convert]::ToString($modeValue, 8)
                    }
                }
                $chmodInfo = [System.Diagnostics.ProcessStartInfo]::new()
                $chmodInfo.FileName = 'chmod'
                $chmodInfo.UseShellExecute = $false
                $null = $chmodInfo.ArgumentList.Add($temporaryMode)
                $null = $chmodInfo.ArgumentList.Add($temporaryPath)
                $chmod = [System.Diagnostics.Process]::Start($chmodInfo)
                $chmod.WaitForExit()
                $chmodExitCode = $chmod.ExitCode
                $chmod.Dispose()
                if ($chmodExitCode -ne 0) {
                    throw 'EndpointOps: could not secure the reputation cache temporary file.'
                }
            }
        }

        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        try {
            $writer.Write($json)
            $writer.Flush()
            $writer.BaseStream.Flush($true)
        }
        finally {
            $writer.Dispose()
            $writer = $null
            $stream = $null
        }

        Move-ReputationCacheFile -SourcePath $temporaryPath -DestinationPath $CachePath
    }
    finally {
        if ($null -ne $writer) { $writer.Dispose() }
        elseif ($null -ne $stream) { $stream.Dispose() }
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
        if ($null -ne $temporaryDirectory -and [System.IO.Directory]::Exists($temporaryDirectory)) {
            [System.IO.Directory]::Delete($temporaryDirectory, $false)
        }
    }
}
