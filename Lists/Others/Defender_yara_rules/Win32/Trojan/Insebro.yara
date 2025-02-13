rule Trojan_Win32_Insebro_A_133721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Insebro.A"
        threat_id = "133721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Insebro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 24 01 01 00 68 ?? ?? 00 10 8b 44 24 34 68 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 83 f8 06 0f 84 6d 01 00 00 8b 4e 08 6a 00 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Insebro_B_139296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Insebro.B"
        threat_id = "139296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Insebro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 03 6a 01 5f 68 ?? ?? ?? ?? ff 75 f8 e8 ?? ?? 00 00 59 85 c0 59 74 0d}  //weight: 1, accuracy: Low
        $x_1_2 = "Navigation blocked</title>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Insebro_C_139500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Insebro.C"
        threat_id = "139500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Insebro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 74 47 a1 ?? ?? ?? ?? 66 c7 45 ?? 01 00 85 c0 66 c7 45 ?? 08 00 75 05 a1 ?? ?? ?? ?? 50 ff d7}  //weight: 2, accuracy: Low
        $x_1_2 = "res://ieocx.dll/" ascii //weight: 1
        $x_1_3 = "res://iehostcx32.dll/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

