Import-Module .\UserRights.ps1 
$users_in_OU = Get-ADUser -filter * -SearchBase 'dc=sans,dc=lab'

$permissions_aval=@('SeTrustedCredManAccessPrivilege','SeNetworkLogonRight','SeTcbPrivilege','SeMachineAccountPrivilege','SeIncreaseQuotaPrivilege','SeInteractiveLogonRight','SeRemoteInteractiveLogonRight','SeBackupPrivilege','SeChangeNotifyPrivilege','SeSystemtimePrivilege','SeTimeZonePrivilege','SeCreatePagefilePrivilege','SeCreateTokenPrivilege','SeCreateGlobalPrivilege','SeCreatePermanentPrivilege','SeCreateSymbolicLinkPrivilege','SeDebugPrivilege','SeDenyNetworkLogonRight','SeDenyBatchLogonRight','SeDenyServiceLogonRight','SeDenyInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight','SeEnableDelegationPrivilege','SeRemoteShutdownPrivilege','SeAuditPrivilege','SeImpersonatePrivilege','SeIncreaseWorkingSetPrivilege','SeIncreaseBasePriorityPrivilege','SeLoadDriverPrivilege','SeLockMemoryPrivilege','SeBatchLogonRight','SeServiceLogonRight','SeSecurityPrivilege','SeRelabelPrivilege','SeSystemEnvironmentPrivilege','SeManageVolumePrivilege','SeProfileSingleProcessPrivilege','SeSystemProfilePrivilege','SeUnsolicitedInputPrivilege','SeUndockPrivilege','SeAssignPrimaryTokenPrivilege','SeRestorePrivilege','SeShutdownPrivilege','SeSyncAgentPrivilege','SeTakeOwnershipPrivilege')
foreach ($permission in $permissions_aval){
$num_of_users=Get-Random -minimum 1 -maximum 25
$users_to_add= $users_in_OU | Get-Random -Count $num_of_users
Write-Host "Adding Permission: $permission to users: $users_to_add"
foreach ($user in $users_to_add){
 Grant-UserRight -Account $user.SamAccountName $permission
}
}