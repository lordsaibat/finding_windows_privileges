<#

VERSION   DATE          AUTHOR
1.0       2015-03-10    Tobias Mccurry
    - Initial Release

Portions developed by Tony Pombo
https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Query-user-26e259b0

#> # Revision History

#Tony Pombo Code
Set-StrictMode -Version 2.0

Add-Type @'
using System;
namespace PS_LSA
{
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Principal;
    using LSA_HANDLE = IntPtr;

    public enum Rights
    {
        SeTrustedCredManAccessPrivilege,      // Access Credential Manager as a trusted caller
        SeNetworkLogonRight,                  // Access this computer from the network
        SeTcbPrivilege,                       // Act as part of the operating system
        SeMachineAccountPrivilege,            // Add workstations to domain
        SeIncreaseQuotaPrivilege,             // Adjust memory quotas for a process
        SeInteractiveLogonRight,              // Allow log on locally
        SeRemoteInteractiveLogonRight,        // Allow log on through Remote Desktop Services
        SeBackupPrivilege,                    // Back up files and directories
        SeChangeNotifyPrivilege,              // Bypass traverse checking
        SeSystemtimePrivilege,                // Change the system time
        SeTimeZonePrivilege,                  // Change the time zone
        SeCreatePagefilePrivilege,            // Create a pagefile
        SeCreateTokenPrivilege,               // Create a token object
        SeCreateGlobalPrivilege,              // Create global objects
        SeCreatePermanentPrivilege,           // Create permanent shared objects
        SeCreateSymbolicLinkPrivilege,        // Create symbolic links
        SeDebugPrivilege,                     // Debug programs
        SeDenyNetworkLogonRight,              // Deny access this computer from the network
        SeDenyBatchLogonRight,                // Deny log on as a batch job
        SeDenyServiceLogonRight,              // Deny log on as a service
        SeDenyInteractiveLogonRight,          // Deny log on locally
        SeDenyRemoteInteractiveLogonRight,    // Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege,          // Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege,            // Force shutdown from a remote system
        SeAuditPrivilege,                     // Generate security audits
        SeImpersonatePrivilege,               // Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege,        // Increase a process working set
        SeIncreaseBasePriorityPrivilege,      // Increase scheduling priority
        SeLoadDriverPrivilege,                // Load and unload device drivers
        SeLockMemoryPrivilege,                // Lock pages in memory
        SeBatchLogonRight,                    // Log on as a batch job
        SeServiceLogonRight,                  // Log on as a service
        SeSecurityPrivilege,                  // Manage auditing and security log
        SeRelabelPrivilege,                   // Modify an object label
        SeSystemEnvironmentPrivilege,         // Modify firmware environment values
        SeManageVolumePrivilege,              // Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege,      // Profile single process
        SeSystemProfilePrivilege,             // Profile system performance
        SeUnsolicitedInputPrivilege,          // "Read unsolicited input from a terminal device"
        SeUndockPrivilege,                    // Remove computer from docking station
        SeAssignPrimaryTokenPrivilege,        // Replace a process level token
        SeRestorePrivilege,                   // Restore files and directories
        SeShutdownPrivilege,                  // Shut down the system
        SeSyncAgentPrivilege,                 // Synchronize directory service data
        SeTakeOwnershipPrivilege              // Take ownership of files or other objects
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_ENUMERATION_INFORMATION
    {
        internal IntPtr PSid;
    }

    internal sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaAddAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaRemoveAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            out IntPtr /*LSA_UNICODE_STRING[]*/ UserRights,
            out ulong CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out ulong CountReturned
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);
    }

    internal sealed class Sid : IDisposable
    {
        public IntPtr pSid = IntPtr.Zero;
        public SecurityIdentifier sid = null;

        public Sid(string account)
        {
            try { sid = new SecurityIdentifier(account); }
            catch { sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier)); }
            Byte[] buffer = new Byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);

            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }

        public void Dispose()
        {
            if (pSid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSid);
                pSid = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Sid() { Dispose(); }
    }

    public sealed class LsaWrapper : IDisposable
    {
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a;

        IntPtr lsaHandle;

        public LsaWrapper() : this(null) { } // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void AddPrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaAddAccountRights(lsaHandle, sid.pSid, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void RemovePrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaRemoveAccountRights(lsaHandle, sid.pSid, false, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public Rights[] EnumerateAccountPrivileges(string account)
        {
            uint ret = 0;
            ulong count = 0;
            IntPtr privileges = IntPtr.Zero;
            Rights[] rights = null;

            using (Sid sid = new Sid(account))
            {
                ret = Win32Sec.LsaEnumerateAccountRights(lsaHandle, sid.pSid, out privileges, out count);
            }
            if (ret == 0)
            {
                rights = new Rights[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_UNICODE_STRING str = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        IntPtr.Add(privileges, i * Marshal.SizeOf(typeof(LSA_UNICODE_STRING))),
                        typeof(LSA_UNICODE_STRING));
                    rights[i] = (Rights)Enum.Parse(typeof(Rights), str.Buffer);
                }
                Win32Sec.LsaFreeMemory(privileges);
                return rights;
            }
            if (ret == STATUS_OBJECT_NAME_NOT_FOUND) return null;  // No privileges assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public string[] EnumerateAccountsWithUserRight(Rights privilege)
        {
            uint ret = 0;
            ulong count = 0;
            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = InitLsaString(privilege.ToString());
            IntPtr buffer = IntPtr.Zero;
            string[] accounts = null;

            ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, rights, out buffer, out count);
            if (ret == 0)
            {
                accounts = new string[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_ENUMERATION_INFORMATION LsaInfo = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, i * Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION))),
                        typeof(LSA_ENUMERATION_INFORMATION));

                    try {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).Translate(typeof(NTAccount)).ToString();
                    } catch (System.Security.Principal.IdentityNotMappedException) {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString();
                    }
                }
                Win32Sec.LsaFreeMemory(buffer);
                return accounts;
            }
            if (ret == STATUS_NO_MORE_ENTRIES) return null;  // No accounts assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper() { Dispose(); }

        // helper functions:
        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe) throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }

    public sealed class TokenManipulator
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        internal sealed class Win32Token
        {
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(
                IntPtr htok,
                bool disall,
                ref TokPriv1Luid newst,
                int len,
                IntPtr prev,
                IntPtr relen
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern IntPtr GetCurrentProcess();

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(
                IntPtr h,
                int acc,
                ref IntPtr phtok
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(
                string host,
                string name,
                ref long pluid
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern bool CloseHandle(
                IntPtr phtok
            );
        }

        public static void AddPrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }

        public static void RemovePrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_DISABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }
    }
}
'@ # This type (PS_LSA) is used by Grant-UserRight, Revoke-UserRight, Get-UserRightsGrantedToAccount, Get-AccountsWithUserRight, Grant-TokenPriviledge, Revoke-TokenPrivilege

function Get-UserRightsGrantedToAccount {
 <#
  .SYNOPSIS
    Gets all user rights granted to an account
  .DESCRIPTION
    Retrieves a list of all the user rights (privileges) granted to one or more accounts. The rights retrieved are those granted directly to the user account, and does not include those rights obtained as part of membership to a group.
  .PARAMETER Account
    Logon name of the account. More than one account can be listed. If the account is not found on the computer, the default domain is searched. To specify a domain, you may use either "DOMAIN\username" or "username@domain.dns" formats. SIDs may be also be specified.
  .PARAMETER Computer
    Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
  .EXAMPLE
    Get-UserRightsGrantedToAccount "bilbo.baggins"

    Returns a list of all user rights granted to bilbo.baggins on the local computer.
  .EXAMPLE
    Get-UserRightsGrantedToAccount -Account "Edward","Karen" -Computer TESTPC

    Returns a list of user rights granted to Edward, and a list of user rights granted to Karen, on the TESTPC system.
  .INPUTS
    String Account
    String Computer
  .OUTPUTS
    String Account
    PS_LSA.Rights Right
  .LINK
    http://msdn.microsoft.com/en-us/library/ms721790.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('User','Username')][String[]] $Account,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Acct in $Account) {
            $output = @{'Account'=$Acct; 'Right'=$lsa.EnumerateAccountPrivileges($Acct); }
            Write-Output (New-Object -Typename PSObject -Prop $output)
        }
    }
} # Gets all user rights granted to an account

function Get-AccountsWithUserRight {
 <#
  .SYNOPSIS
    Gets all accounts that are assigned a specified privilege
  .DESCRIPTION
    Retrieves a list of all accounts that hold a specified right (privilege). The accounts returned are those that hold the specified privilege directly through the user account, not as part of membership to a group.
  .PARAMETER Right
    Name of the right to query. More than one right may be listed.

    Possible values: 
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .PARAMETER Computer
    Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
  .EXAMPLE
    Get-AccountsWithUserRight SeServiceLogonRight

    Returns a list of all accounts that hold the "Log on as a service" right.
  .EXAMPLE
    Get-AccountsWithUserRight -Right SeServiceLogonRight,SeDebugPrivilege -Computer TESTPC

    Returns a list of accounts that hold the "Log on as a service" right, and a list of accounts that hold the "Debug programs" right, on the TESTPC system.
  .INPUTS
    PS_LSA.Rights Right
    String Computer
  .OUTPUTS
    String Account
    String Right
  .LINK
    http://msdn.microsoft.com/en-us/library/ms721792.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] $Right,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Priv in $Right) {
            $output = @{'Account'=$lsa.EnumerateAccountsWithUserRight($Priv); 'Right'=$Priv; }
            Write-Output (New-Object -Typename PSObject -Prop $output)
        }
    }
} # Gets all accounts that are assigned a specified privilege


#Tony Pombo Code

#Code from Will Schroeder (@harmj0y)
#Code from Powerview to make my code not reliant on AD Commandlet
#https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

filter Get-DomainSearcher {
<#
    .SYNOPSIS
        Helper used by various functions that takes an ADSpath and
        domain specifier and builds the correct ADSI searcher object.
    .PARAMETER Domain
        The domain to use for the query, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER ADSprefix
        Prefix to set for the searcher (like "CN=Sites,CN=Configuration")
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-DomainSearcher -Domain testlab.local
    .EXAMPLE
        PS C:\> Get-DomainSearcher -Domain testlab.local -DomainController SECONDARY.dev.testlab.local
#>

    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    if(-not $Credential) {
        if(-not $Domain) {
            $Domain = (Get-NetDomain).name
        }
        elseif(-not $DomainController) {
            try {
                # if there's no -DomainController specified, try to pull the primary DC to reflect queries through
                $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
            }
        }
    }
    elseif (-not $DomainController) {
        # if a DC isn't specified
        try {
            $DomainController = ((Get-NetDomain -Credential $Credential).PdcRoleOwner).Name
        }
        catch {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }

        if(!$DomainController) {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }
    }

    $SearchString = "LDAP://"

    if($DomainController) {
        $SearchString += $DomainController
        if($Domain){
            $SearchString += '/'
        }
    }

    if($ADSprefix) {
        $SearchString += $ADSprefix + ','
    }

    if($ADSpath) {
        if($ADSpath -Match '^GC://') {
            # if we're searching the global catalog
            $DN = $AdsPath.ToUpper().Trim('/')
            $SearchString = ''
        }
        else {
            if($ADSpath -match '^LDAP://') {
                if($ADSpath -match "LDAP://.+/.+") {
                    $SearchString = ''
                }
                else {
                    $ADSpath = $ADSpath.Substring(7)
                }
            }
            $DN = $ADSpath
        }
    }
    else {
        if($Domain -and ($Domain.Trim() -ne "")) {
            $DN = "DC=$($Domain.Replace('.', ',DC='))"
        }
    }

    $SearchString += $DN
    Write-Verbose "Get-DomainSearcher search string: $SearchString"

    if($Credential) {
        Write-Verbose "Using alternate credentials for LDAP connection"
        $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
    }
    else {
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    }

    $Searcher.PageSize = $PageSize
    $Searcher.CacheResults = $False
    $Searcher
}

filter Get-NetDomain {
<#
    .SYNOPSIS
        Returns a given domain object.
    .PARAMETER Domain
        The domain name to query for, defaults to the current domain.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetDomain -Domain testlab.local
    .EXAMPLE
        PS C:\> "testlab.local" | Get-NetDomain
    .LINK
        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
#>

    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Credential) {
        
        Write-Verbose "Using alternate credentials for Get-NetDomain"

        if(!$Domain) {
            # if no domain is supplied, extract the logon domain from the PSCredential passed
            $Domain = $Credential.GetNetworkCredential().Domain
            Write-Verbose "Extracted domain '$Domain' from -Credential"
        }
   
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Verbose "The specified domain does '$Domain' not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
            $Null
        }
    }
    elseif($Domain) {
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Verbose "The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else {
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
}

function Get-NetComputer {
<#
    .SYNOPSIS
        This function utilizes adsisearcher to query the current AD context
        for current computer objects. Based off of Carlos Perez's Audit.psm1
        script in Posh-SecMod (link below).
    .PARAMETER ComputerName
        Return computers with a specific name, wildcards accepted.
    .PARAMETER SPN
        Return computers with a specific service principal name, wildcards accepted.
    .PARAMETER OperatingSystem
        Return computers with a specific operating system, wildcards accepted.
    .PARAMETER ServicePack
        Return computers with a specific service pack, wildcards accepted.
    .PARAMETER Filter
        A customized ldap filter string to use, e.g. "(description=*admin*)"
    .PARAMETER Printers
        Switch. Return only printers.
    .PARAMETER Ping
        Switch. Ping each host to ensure it's up before enumerating.
    .PARAMETER FullData
        Switch. Return full computer objects instead of just system names (the default).
    .PARAMETER Domain
        The domain to query for computers, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    
    .PARAMETER SiteName
        The AD Site name to search for computers.
    .PARAMETER Unconstrained
        Switch. Return computer objects that have unconstrained delegation.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetComputer
        
        Returns the current computers in current domain.
    .EXAMPLE
        PS C:\> Get-NetComputer -SPN mssql*
        
        Returns all MS SQL servers on the domain.
    .EXAMPLE
        PS C:\> Get-NetComputer -Domain testing
        
        Returns the current computers in 'testing' domain.
    .EXAMPLE
        PS C:\> Get-NetComputer -Domain testing -FullData
        
        Returns full computer objects in the 'testing' domain.
    .LINK
        https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = '*',

        [String]
        $SPN,

        [String]
        $OperatingSystem,

        [String]
        $ServicePack,

        [String]
        $Filter,

        [Switch]
        $Printers,

        [Switch]
        $Ping,

        [Switch]
        $FullData,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $SiteName,

        [Switch]
        $Unconstrained,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        # so this isn't repeated if multiple computer names are passed on the pipeline
        $CompSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize -Credential $Credential
    }

    process {

        if ($CompSearcher) {

            # if we're checking for unconstrained delegation
            if($Unconstrained) {
                Write-Verbose "Searching for computers with for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            # set the filters for the seracher if it exists
            if($Printers) {
                Write-Verbose "Searching for printers"
                # $CompSearcher.filter="(&(objectCategory=printQueue)$Filter)"
                $Filter += "(objectCategory=printQueue)"
            }
            if($SPN) {
                Write-Verbose "Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if($OperatingSystem) {
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if($ServicePack) {
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if($SiteName) {
                $Filter += "(serverreferencebl=$SiteName)"
            }

            $CompFilter = "(&(sAMAccountType=805306369)(dnshostname=$ComputerName)$Filter)"
            Write-Verbose "Get-NetComputer filter : '$CompFilter'"
            $CompSearcher.filter = $CompFilter

            try {
                $Results = $CompSearcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {
                    $Up = $True
                    if($Ping) {
                        # TODO: how can these results be piped to ping for a speedup?
                        $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                    }
                    if($Up) {
                        # return full data objects
                        if ($FullData) {
                            # convert/process the LDAP fields for each result
                            $Computer = Convert-LDAPProperty -Properties $_.Properties
                            $Computer.PSObject.TypeNames.Add('PowerView.Computer')
                            $Computer
                        }
                        else {
                            # otherwise we're just returning the DNS host name
                            $_.properties.dnshostname
                        }
                    }
                }
                $Results.dispose()
                $CompSearcher.dispose()
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}

#End Will Schroeder code

#Start Tobias Mccurry Code
function Find-BadPrivileges{
 <#
  .SYNOPSIS
    Find Account With BadPrivileges
  .DESCRIPTION
    Find accounts with BadPrivileges
  .PARAMETER AccountNameOnly
    Show the account name only

    Bad Privilieges: 
          SeCreateTokenPrivilege               Create a token object
          SeDebugPrivilege                     Debug programs
          SeImpersonatePrivilege               Impersonate a client after authentication
          SeLoadDriverPrivilege                Load and unload device drivers
          SeRestorePrivilege                   Restore files and directories
          SeTakeOwnershipPrivilege             Take ownership of files or other objects
          SeTcbPrivilege                       Act as part of the operating system
    
    Alternative Bad Privileges (Based on Foxglovesecurity post:https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/ :
          SeAssignPrimaryTokenPrivilege        Replace a process level token
          SeBackupPrivilege                    Back up files and directories

  .EXAMPLE
    Find-BadPrivileges 

    Lists the OU, Group, User with the bad privileges enabled.

    Find-BadPrivileges -AccountNameOnly

    Lists the User accounts with the bad privileges enabled.

    Find-BadPrivileges -OU "OUName"

    Lists the User accounts in an OU with the bad privileges enabled

    Find-BadPrivileges -GROUP "GroupName"

    Lists the User accounts in a Group with the bad privileges enabled

    Find-BadPrivileges -ComputerName TEST

    List the User accounts on a remote test with bad privileges enabled


  .INPUTS
    None
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/aa375202.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
    https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/


 #>

 [CmdletBinding()]
param
(
    [parameter(Mandatory=$false)][Switch]$AccountNameOnly,
    [parameter(Mandatory=$false)][String]$OU,
    [parameter(Mandatory=$false)][String]$Group,
    [parameter(Mandatory=$false)][Alias('HostName')][ValidateNotNullOrEmpty()][String]$ComputerName = 'localhost'
   
)

$bad_privileges=@('SeCreateTokenPrivilege','SeDebugPrivilege','SeImpersonatePrivilege','SeLoadDriverPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege','SeTcbPrivilege')
$add_bad_privs=@('SeAssignPrimaryTokenPrivilege','SeBackupPrivilege')


Write-Host "Accounts with Bad Privileges on $ComputerName"
write-host " "

foreach ($priv in $bad_privileges){
$Accounts=""
try{
$Accounts=Get-AccountsWithUserRight -Right $priv -Computer $ComputerName | Select-Object -ExpandProperty Account
}
catch{
Write-Verbose "No Accounts with those rights"
}
if ($Accounts){
 Write-Host "Accounts with " $priv -ForegroundColor Red
 foreach ($Account in $Accounts){
 $Name=$Account.Split('\')[1]
  if ($AccountNameOnly){
   Write-Host $Name
  }
   else {
   $strName=$Name
   $strFilter = "(&(objectCategory=User)(samAccountName=$strName))"
   $objSearcher=New-Object System.DirectoryServices.DirectorySearcher
   $objSearcher.Filter = $strFilter
   $objPath=$objSearcher.FindOne()
   try{
   $objUser=$ObjPath.GetDirectoryEntry()
   $membersof=$objUser.memberoF
    foreach ($memberof in $membersof){
    Write-Host $memberof
     }
    }
    catch{
     Write-Verbose "Error with $Name" 
     Write-Verbose "***Trying different method***" 
     try{
     $members=Get-ADGroupMember -Identity $Name
     }
      catch{
      $members=""
      Write-Host "Local Account: $Name"
      }
     foreach ($member in $members){
       if ($member){
       $member.distinguishedName
       }
      }
     }
     Write-Verbose "***End Trying***" 
    }
   }
 }
 Write-Host " "
}


Write-Host ""
Write-Host "Accounts with potentially Bad Privilege on $ComputerName" -ForegroundColor Yellow
foreach ($priv in $add_bad_privs){
$Accounts=""
try{
$Accounts=Get-AccountsWithUserRight -Right $priv -Computer $ComputerName | Select-Object -ExpandProperty Account
}
catch{
Write-Verbose "No Accounts with those rights"
}
if ($Accounts){
 Write-Host "Accounts with " $priv -ForegroundColor Yellow
 foreach ($Account in $Accounts){
 $Name=$Account.Split('\')[1]
  if ($AccountNameOnly){
   Write-Host $Name
  }
   else {
   $strName=$Name
   $strFilter = "(&(objectCategory=User)(samAccountName=$strName))"
   $objSearcher=New-Object System.DirectoryServices.DirectorySearcher
   $objSearcher.Filter = $strFilter
   $objPath=$objSearcher.FindOne()
   try{
   $objUser=$ObjPath.GetDirectoryEntry()
   $membersof=$objUser.memberoF
    foreach ($memberof in $membersof){
    Write-Host $memberof
     }
    }
    catch{
     Write-Verbose "Error with $Name" 
     Write-Verbose "***Trying different method***" 
     try{
     $members=Get-ADGroupMember -Identity $Name

     }
      catch{
      $members=""
      Write-Host "Local Account: $Name"
      }
     foreach ($member in $members){
       if ($member){
       $member.distinguishedName
       }
      }
     }
     Write-Verbose "***End Trying***" 
    }
   }
  }
 }
} 

function Find-BadPrivilegesDomain{
 <#
  .SYNOPSIS
    Find all the Accounts With BadPrivileges
  .DESCRIPTION
    Find accounts with BadPrivileges

    Bad Privilieges: 
          SeCreateTokenPrivilege               Create a token object
          SeDebugPrivilege                     Debug programs
          SeImpersonatePrivilege               Impersonate a client after authentication
          SeLoadDriverPrivilege                Load and unload device drivers
          SeRestorePrivilege                   Restore files and directories
          SeTakeOwnershipPrivilege             Take ownership of files or other objects
          SeTcbPrivilege                       Act as part of the operating system
    
    Alternative Bad Privileges (Based on Foxglovesecurity post:https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/ :
          SeAssignPrimaryTokenPrivilege        Replace a process level token
          SeBackupPrivilege                    Back up files and directories

  .EXAMPLE
    Find-BadPrivilegesDomain 

    List the User accounts with bad privileges on every system in the doamin 


  .INPUTS
    None
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/aa375202.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
    https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/


 #>
 
 $Computers = Get-ADComputer -Filter *
 
 $Computers | ForEach-Object {  
 Find-BadPrivileges -ComputerName $_
 Write-Host " "
 }
   
}

#End Tobias Mccurry Code
