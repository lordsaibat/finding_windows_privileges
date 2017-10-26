<#
Three external files are needed to run this script.
----OUs.csv Which only needs one column with Name being at the top.
Ex:
Name
Ou1
Ou2
Ou3

----Groups.csv Which only needs one column with Name being at the top.
Ex:
Name
Group1
Group2
Group3

----Users.csv Which needs 11 columns structured in the following manner.
Ex:
Name,SamAccount,cn,sn,Description,Department,Employee,,Path,Enabled,Password
Richard,RJones,RJones,Jones,,,cn=users,dc=sans.lab,dc=com,$TRUE,Pass@W0rd1
Abraham,ASapien,ASapien,Sapien,,,cn=users,dc=sans.lab,dc=com,$TRUE,Pass@W0rd1
 Emil,EBlonsky,EBlonsky,Blonsky,,,cn=users,dc=sans.lab,dc=com,$TRUE,Pass@W0rd1
Abraxas,AAbraxas,AAbraxas,Abraxas,,,cn=users,dc=sans.lab,dc=com,$TRUE,Pass@W0rd1



What does the script do?
It will create 1-75 Ous, inside each Ous it will create 1-75 groups.
It will then take no less than 100 users from users.csv and 

VERSION   DATE          AUTHOR
1.0       8/27/2017	Tobias Mccurry


#> # Revision History
$OUs = Import-Csv OUs.csv | where Name -ne ""
$groups = Import-Csv groups.csv | where Name -ne ""
$users = Import-Csv users.csv | where Name -ne ""
$num_of_OUs_to_add = Get-Random -minimum 1 -maximum 75
$OUs_to_add= $groups | Get-Random -Count $num_of_OUs_to_add
foreach ($ou in $OUs_to_add)
 {
 New-ADOrganizationalUnit -Name $ou.Name -ProtectedFromAccidentalDeletion 0
 $num_of_groups_to_add = Get-Random -minimum 1 -maximum 75
 $groups_to_add= $groups | Get-Random -Count $num_of_groups_to_add
 Write-Host "Groups that are going to be added to $ou.Name:"
 Write-Host "$groups_to_add"
 foreach ($group in $groups_to_add)
  {
  $OU_Name=$ou.Name
  $Path_build="OU=" + $OU_Name + ",DC=sans,DC=lab"
  New-ADGroup -Name $group.Name -GroupScope 0 -Path $Path_build
  Write-Host "New-ADGroup -Name $group.Name -GroupScope 0 -Path $Path_build"
  }
}
Write-Host "Finished creating OUs and Groups"

 $num_of_users_to_add = Get-Random -minimum 100 
 $users_to_add= $users | Get-Random -Count $num_of_users_to_add
 Write-Host "Users going to add: $users_to_add"
 foreach ($user in $users_to_add)
 {
  $ou=Get-ADOrganizationalUnit -Filter * | Get-Random -Count 1
  $userprinicpalname = $user.SamAccount + "@sans.lab"
  $Path_build=$ou.DistinguishedName
  New-ADUser -SamAccountName $user.SamAccount -UserPrincipalName $userprinicpalname -Name $user.Name -DisplayName $user.Name -GivenName $user.cn -SurName $user.sn -Department $user.Department -Path $Path_build -AccountPassword (ConvertTo-SecureString $user.Password -AsPlainText -force) -Enabled $True -PasswordNeverExpires $True -PassThru
  Write-Host "New-ADUser -SamAccountName $user.SamAccount -UserPrincipalName $userprinicpalname -Name $user.Name -DisplayName $user.Name -GivenName $user.cn -SurName $user.sn -Department $user.Department -Path $Path_build -AccountPassword (ConvertTo-SecureString $user.Password -AsPlainText -force) -Enabled $True -PasswordNeverExpires $True -PassThru"
  }
Write-Host "Finished Adding users"


$allOUs = Get-ADOrganizationalUnit -Filter {objectCategory -eq "CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=sans,DC=lab"}
 foreach ($ou in $allOUs){
 #Load all the users in the OU
 #Load all the users into a variable
 $Path_build=$ou.DistinguishedName
 $users_in_OU = Get-ADUser -filter * -SearchBase $Path_build

 #Load Groups into a variable
 $groups_in_OU = Get-ADGroup -filter * -properties GroupCategory -SearchBase $Path_build

 foreach ($group_in_OU in $groups_in_OU){
  $num_of_users_to_add = Get-Random -minimum 20 
  $mixed = $users_in_OU + $groups_in_OU
  $users_to_add=$mixed | Get-Random -Count $num_of_users_to_add
  Add-ADGroupMember -Identity $group_in_OU.DistinguishedName -Members $users_to_add.DistinguishedName
  Write-Host "Add-ADGroupMember -Identity $group_in_OU.DistinguishedName -Members $users_to_add.DistinguishedName"
  }
 
}
Write-Host "Finished adding users and groups in each OU"
