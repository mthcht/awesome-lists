rule Trojan_Win32_LogOffscripts_MK_2147946871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LogOffscripts.MK"
        threat_id = "2147946871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LogOffscripts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "gpupdate.exe /force & exit" wide //weight: 1
        $n_1_4 = "aa06e39e-7876-4ba3-beee-42bd80ff363a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_LogOffscripts_MK_2147946871_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LogOffscripts.MK"
        threat_id = "2147946871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LogOffscripts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "gpupdate.exe /force & exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LogOffscripts_AM_2147948228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LogOffscripts.AM"
        threat_id = "2147948228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LogOffscripts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "gpupdate.exe /force & exit" wide //weight: 1
        $n_1_4 = "506079a9-3427-44b1-b745-a1c985d03213" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

