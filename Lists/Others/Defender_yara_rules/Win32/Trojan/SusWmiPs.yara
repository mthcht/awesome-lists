rule Trojan_Win32_SusWmiPs_A_2147954146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWmiPs.A"
        threat_id = "2147954146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "-ClassName" ascii //weight: 1
        $x_1_4 = "Win32_OperatingSystem" ascii //weight: 1
        $n_1_5 = "69802c98-2ch2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusWmiPs_B_2147954147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWmiPs.B"
        threat_id = "2147954147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "Win32_NetworkAdapterConfiguration" ascii //weight: 1
        $x_1_4 = "-Filter IPEnabled=TRUE -ComputerName" ascii //weight: 1
        $n_1_5 = "69802c98-2ci2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusWmiPs_C_2147954148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWmiPs.C"
        threat_id = "2147954148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "win32_physicalmemory" ascii //weight: 1
        $n_1_4 = "69802c98-2cj2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusWmiPs_D_2147954149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWmiPs.D"
        threat_id = "2147954149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWmiPs"
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
        $n_1_8 = "69802c98-2ck2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule Trojan_Win32_SusWmiPs_E_2147954150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWmiPs.E"
        threat_id = "2147954150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic qfe get" ascii //weight: 1
        $x_1_2 = "description" ascii //weight: 1
        $x_1_3 = "installedOn" ascii //weight: 1
        $x_1_4 = "/format:csv" ascii //weight: 1
        $n_1_5 = "69802c98-2cl2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

