rule Trojan_Win32_ZShell_GVVA_2147975047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZShell.GVVA!MTB"
        threat_id = "2147975047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "curl" wide //weight: 10
        $x_10_2 = "-ksfL" wide //weight: 10
        $x_10_3 = "https://" wide //weight: 10
        $x_10_4 = "| zsh" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

