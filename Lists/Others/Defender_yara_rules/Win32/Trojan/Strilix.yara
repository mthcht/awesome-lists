rule Trojan_Win32_Strilix_A_2147727596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strilix.A!dha"
        threat_id = "2147727596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strilix"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {59 57 68 80 00 00 00 6a 03 57 6a 07 8b d8 68 00 00 00 80 56 89 3b}  //weight: 10, accuracy: High
        $x_10_2 = {b9 50 85 33 01 81 e9 00 10 33 01 83 c1 fb 03 c8}  //weight: 10, accuracy: High
        $x_5_3 = {c7 06 44 33 22 11 89 9e b0 00 00 00 89 5e 10 89 5e 14 89 5e 18 89 5e 1c 89 5e 20 89 5e 74}  //weight: 5, accuracy: High
        $x_5_4 = {c7 00 44 33 22 11 48 89 b0 d8 00 00 00 48 89 70 10 48 89 70 18 89 70 20 48 89 70 74 b8 20 00 00 00 ba b0 10 00 00 44 8d 48 e4 33 c9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

