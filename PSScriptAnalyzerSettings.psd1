@{
    Severity     = @('ParseError', 'Error', 'Warning')
    ExcludeRules = @(
        # PSProvideCommentHelp is excluded as a guard against an intermittent
        # PSScriptAnalyzer 1.25.0 engine defect. During recursive scans, the
        # rule can throw NullReferenceException in
        # Helper.GetExportedFunction -> CommandInfo.ResolveParameter when the
        # module .psm1 calls Export-ModuleMember. The rule is Information-level
        # and therefore already outside the selected severity filter; this
        # exclusion protects future changes that might include Information.
        'PSProvideCommentHelp'
    )
    Rules        = @{
        PSPlaceOpenBrace = @{
            Enable     = $true
            OnSameLine = $true
        }
    }
}
