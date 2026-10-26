# Invoke-EndpointOpsRequest is private (decision 63). Transport tests still exercise it directly, so
# this proxy forwards every argument into the module scope. Dot-source it after Import-Module.
function Invoke-EndpointOpsRequest {
    & (Get-Module EndpointOps) Invoke-EndpointOpsRequest @args
}
