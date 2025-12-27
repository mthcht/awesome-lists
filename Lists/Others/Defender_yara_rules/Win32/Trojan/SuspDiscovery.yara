rule Trojan_Win32_SuspDiscovery_A_2147955619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDiscovery.A"
        threat_id = "2147955619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic.exe" ascii //weight: 1
        $x_1_2 = "csproduct" ascii //weight: 1
        $x_1_3 = "get UUID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspDiscovery_B_2147955620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDiscovery.B"
        threat_id = "2147955620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ntfsinfo64.exe" ascii //weight: 1
        $x_1_2 = "-accepteula" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspDiscovery_C_2147955621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDiscovery.C"
        threat_id = "2147955621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /create /sc MINUTE /tn" ascii //weight: 1
        $x_1_2 = "Windows Update Security Patches" ascii //weight: 1
        $x_1_3 = "/tr" wide //weight: 1
        $x_1_4 = "programdata\\enc.exe" ascii //weight: 1
        $x_1_5 = "/F" wide //weight: 1
        $x_1_6 = "/mo " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspDiscovery_C_2147955621_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDiscovery.C"
        threat_id = "2147955621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /create /sc MINUTE /tn" ascii //weight: 1
        $x_1_2 = "Windows Update Security" ascii //weight: 1
        $x_1_3 = "/tr" wide //weight: 1
        $x_1_4 = "regsvr32.exe /i" ascii //weight: 1
        $x_1_5 = "programdata\\network.dll" wide //weight: 1
        $x_1_6 = "/F" wide //weight: 1
        $x_1_7 = "/mo " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspDiscovery_D_2147955622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDiscovery.D"
        threat_id = "2147955622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /create /ST" ascii //weight: 1
        $x_1_2 = "/SC MINUTE /MO" ascii //weight: 1
        $x_1_3 = "svchost.exe" ascii //weight: 1
        $x_1_4 = "/TN StorSyncSvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspDiscovery_E_2147955623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDiscovery.E"
        threat_id = "2147955623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sc.exe create" ascii //weight: 1
        $x_1_2 = "MPSEvtMan" ascii //weight: 1
        $x_1_3 = "binPath=" ascii //weight: 1
        $x_1_4 = "Windows Firewall Policy Event Manager" ascii //weight: 1
        $x_1_5 = "svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspDiscovery_F_2147955624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDiscovery.F"
        threat_id = "2147955624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sc.exe create" ascii //weight: 1
        $x_1_2 = "RasConMan" ascii //weight: 1
        $x_1_3 = "binPath=" ascii //weight: 1
        $x_1_4 = "Remote Access Connection Manager" ascii //weight: 1
        $x_1_5 = "svchost.exe -k RasConMan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspDiscovery_G_2147955625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDiscovery.G"
        threat_id = "2147955625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /Create /F /XML" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "Wininet.xml" ascii //weight: 1
        $x_1_4 = "/tn" wide //weight: 1
        $x_1_5 = "Microsoft\\Windows\\Maintenance\\Wininet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspDiscovery_H_2147955626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDiscovery.H"
        threat_id = "2147955626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe" ascii //weight: 1
        $x_1_2 = "/Run" wide //weight: 1
        $x_1_3 = "/tn" wide //weight: 1
        $x_1_4 = "Microsoft\\Windows\\Maintenance\\Wininet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

