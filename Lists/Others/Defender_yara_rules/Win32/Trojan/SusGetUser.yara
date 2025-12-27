rule Trojan_Win32_SusGetUser_MK_2147945918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusGetUser.MK"
        threat_id = "2147945918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusGetUser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "net user & exit" wide //weight: 1
        $n_1_4 = "aa06e39e-7876-4ba3-beee-42bd80ff362d" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusGetUser_MK_2147945918_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusGetUser.MK"
        threat_id = "2147945918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusGetUser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "net user & exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

