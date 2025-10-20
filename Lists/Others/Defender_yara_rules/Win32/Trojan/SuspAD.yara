rule Trojan_Win32_SuspAD_A_2147955587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspAD.A"
        threat_id = "2147955587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nltest.exe /dclist:" ascii //weight: 1
        $x_1_2 = "nltest.exe /domain_trusts /all_trusts" ascii //weight: 1
        $x_1_3 = "net.exe localgroup administrators" ascii //weight: 1
        $x_1_4 = "whoami /groups" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspAD_B_2147955588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspAD.B"
        threat_id = "2147955588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WMIObject Win32_NTDomain" ascii //weight: 1
        $x_1_3 = "findstr DomainController" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspAD_C_2147955589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspAD.C"
        threat_id = "2147955589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ipconfig.exe /all" ascii //weight: 1
        $x_1_2 = "net.exe user" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspAD_D_2147955590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspAD.D"
        threat_id = "2147955590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "qbotDiscovery.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspAD_E_2147955591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspAD.E"
        threat_id = "2147955591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "arp -a" ascii //weight: 1
        $x_1_2 = "ipconfig.exe /all" ascii //weight: 1
        $x_1_3 = "getmac.exe" ascii //weight: 1
        $x_1_4 = "route PRINT" ascii //weight: 1
        $x_1_5 = "netstat -nao" ascii //weight: 1
        $x_1_6 = "net.exe localgroup" ascii //weight: 1
        $x_1_7 = "whoami.exe /all" ascii //weight: 1
        $x_1_8 = "netsh.exe advfirewall firewall show rule name=all" ascii //weight: 1
        $x_1_9 = "tasklist.exe /svc" ascii //weight: 1
        $x_1_10 = "powershell.exe -enc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

