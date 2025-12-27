rule Trojan_Win32_SusDiscovery_A_2147954166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDiscovery.A"
        threat_id = "2147954166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic.exe" ascii //weight: 1
        $x_1_2 = "csproduct" ascii //weight: 1
        $x_1_3 = "get UUID" ascii //weight: 1
        $n_1_4 = "if9044b2-c2ab-4b43-91d5-bb5aeddc4d76" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusDiscovery_B_2147954167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDiscovery.B"
        threat_id = "2147954167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ntfsinfo64.exe" ascii //weight: 1
        $x_1_2 = "-accepteula" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $n_1_4 = "jf9044b2-c2ab-4b43-91d5-bb5aeddc4d76" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusDiscovery_C_2147954168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDiscovery.C"
        threat_id = "2147954168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDiscovery"
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
        $n_1_7 = "kf9044b2-c2ab-4b43-91d5-bb5aeddc4d76" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusDiscovery_C_2147954168_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDiscovery.C"
        threat_id = "2147954168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDiscovery"
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
        $n_1_8 = "lf9044b2-c2ab-4b43-91d5-bb5aeddc4d76" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusDiscovery_D_2147954169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDiscovery.D"
        threat_id = "2147954169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /create /ST" ascii //weight: 1
        $x_1_2 = "/SC MINUTE /MO" ascii //weight: 1
        $x_1_3 = "svchost.exe" ascii //weight: 1
        $x_1_4 = "/TN StorSyncSvc" ascii //weight: 1
        $n_1_5 = "4b79ffab-a220-4ed5-a63d-1f1a9045113c" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusDiscovery_E_2147954170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDiscovery.E"
        threat_id = "2147954170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDiscovery"
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
        $n_1_6 = "4b79ffab-a220-4ed5-a63d-1f1a9045113a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusDiscovery_F_2147954171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDiscovery.F"
        threat_id = "2147954171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDiscovery"
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
        $n_1_6 = "4b79ffab-a220-4ed5-a63d-1f1a9045113b" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusDiscovery_G_2147954172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDiscovery.G"
        threat_id = "2147954172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDiscovery"
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
        $n_1_6 = "4b79ffab-a220-4ed5-a63d-1f1a9045113d" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusDiscovery_H_2147954173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDiscovery.H"
        threat_id = "2147954173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe" ascii //weight: 1
        $x_1_2 = "/Run" wide //weight: 1
        $x_1_3 = "/tn" wide //weight: 1
        $x_1_4 = "Microsoft\\Windows\\Maintenance\\Wininet" ascii //weight: 1
        $n_1_5 = "4b79ffab-a220-4ed5-a63d-1f1a9045113e" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

