rule Trojan_Win32_MPTamperDelete_A_2147812066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MPTamperDelete.A"
        threat_id = "2147812066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MPTamperDelete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "rmdir" wide //weight: 10
        $x_5_2 = ":\\programdata\\microsoft\\windows defender" wide //weight: 5
        $x_5_3 = ":\\program files\\windows defender" wide //weight: 5
        $x_5_4 = ":\\program files (x86)\\windows defender" wide //weight: 5
        $x_10_5 = "-recurse" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

