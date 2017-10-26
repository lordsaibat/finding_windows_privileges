# finding_windows_privileges
Windows privileges add to the complexity of Windows user permissions.
Each additional user added to a group could lead to a domain compromise if not evaluated. 
Privileges can override permission causing a gap of perceived effective permission.

Based on code from Tony Pombo
https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Query-user-26e259b0

The Active Directory commandlet must be installed. 
Using the commandlet, a list of computers will be pulled from Active Directory. 
Using that list, each computer will then be queried for its privileged users. 
If the Active Directory commandlet is not installed visit: 
https://blogs.technet.microsoft.com/ashleymcglone/2016/02/26/install-the-active-directory-powershell-module-on-windows-10/


To search for users with Bad Privileges on the localhost
'''
Find-BadPrivilege
'''

To seach for users with Bad Privileges on all the computers in the domain

'''
Find-BadPrivilegeDomain
''''

Learn more about the script and how this script filled a gap in privileges at:
