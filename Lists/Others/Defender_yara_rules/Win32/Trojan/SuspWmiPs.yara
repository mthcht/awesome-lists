rule Trojan_Win32_SuspWmiPs_A_2147955599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiPs.A"
        threat_id = "2147955599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "-ClassName" ascii //weight: 1
        $x_1_4 = "Win32_OperatingSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspWmiPs_B_2147955600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiPs.B"
        threat_id = "2147955600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "Win32_NetworkAdapterConfiguration" ascii //weight: 1
        $x_1_4 = "-Filter IPEnabled=TRUE -ComputerName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspWmiPs_C_2147955601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiPs.C"
        threat_id = "2147955601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "win32_physicalmemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspWmiPs_D_2147955602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiPs.D"
        threat_id = "2147955602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "Win32_Processor" ascii //weight: 1
        $x_1_4 = "win32_desktopmonitor" ascii //weight: 1
        $x_1_5 = "win32_videocontroller" ascii //weight: 1
        $x_1_6 = "gdr" wide //weight: 1
        $x_1_7 = "-PSProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_SuspWmiPs_E_2147955603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiPs.E"
        threat_id = "2147955603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic qfe get" ascii //weight: 1
        $x_1_2 = "description" ascii //weight: 1
        $x_1_3 = "installedOn" ascii //weight: 1
        $x_1_4 = "/format:csv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

