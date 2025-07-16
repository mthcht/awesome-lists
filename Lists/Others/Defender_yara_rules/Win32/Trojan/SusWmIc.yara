rule Trojan_Win32_SusWmIc_MK_2147945914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWmIc.MK"
        threat_id = "2147945914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWmIc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic /node:localhost /namespace:" wide //weight: 1
        $x_1_2 = "/format:list" wide //weight: 1
        $n_1_3 = "aa06e39e-7876-4ba3-beee-42bd80ff362g" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusWmIc_MK_2147945914_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWmIc.MK"
        threat_id = "2147945914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWmIc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic /node:localhost /namespace:" wide //weight: 1
        $x_1_2 = "/format:list" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

