rule Trojan_Win32_SusNetUser_MK_2147945916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusNetUser.MK"
        threat_id = "2147945916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusNetUser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "net localgroup & exit" wide //weight: 1
        $n_1_4 = "ba06e39e-7876-4ba3-beee-42bd80ff362e" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusNetUser_MK_2147945916_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusNetUser.MK"
        threat_id = "2147945916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusNetUser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "net localgroup & exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

