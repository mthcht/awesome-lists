rule Trojan_Win32_Tesch_A_2147679829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tesch.A"
        threat_id = "2147679829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tesch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 01 8d 46 14 50 8b 46 20 ff 70 14 ff 15 ?? ?? ?? ?? 83 f8 ff 75 ?? ff 76 20 56}  //weight: 10, accuracy: Low
        $x_1_2 = {6a 23 8d 47 04 68 ?? ?? ?? ?? 50 c7 07 32 33 0d 0a e8 ?? ?? ?? ?? 6a 29 66 c7 47 27 0d 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {50 c7 06 32 33 0d 0a e8 ?? ?? ?? ?? 83 c4 1c 66 c7 46 27 0d 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tesch_B_2147683731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tesch.B"
        threat_id = "2147683731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tesch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 64 2e 25 64 2e 25 64 2e 25 64 00 25 73 00 00 6a 61 76 61 66 72 6f 67 73 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 75 6e 5c 00 00 00 00 47 61 6d 65 53 65 72 76}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 3f 00 3f 00 5c 00 25 00 77 00 73 00 5c 00 00 00 00 00 22 00 25 00 73 00 22 00 00 00 00 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 00 00 5c 00 5c 00 3f 00 5c 00 25 00 77 00 73 00 00 00 25 00 77 00 73 00 00 00 57 00 49 00 4e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

