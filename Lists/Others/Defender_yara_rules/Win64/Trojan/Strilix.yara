rule Trojan_Win64_Strilix_A_2147727597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strilix.A!dha"
        threat_id = "2147727597"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strilix"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 b8 8d 56 e6 8c 41 8b c0 f7 e9 03 d1 c1 fa 0b 8b c2 c1 e8 1f 03 d0 69 c2 89 0e 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {48 89 b8 08 01 00 00 c7 00 44 33 22 11 48 89 b0 d8 00 00 00 48 89 70 10 48 89 70 18 89 70 20 48 89 70 74}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Strilix_B_2147727598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strilix.B!dha"
        threat_id = "2147727598"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strilix"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 4c 24 24 48 8b 0d 91 58 01 00 c7 44 24 20 10 00 00 00 c7 44 24 28 07 00 00 00 44 89 44 24 34 c7 44 24 38 b8 0b 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {41 b8 8d 56 e6 8c 41 8b c0 f7 e9 03 d1 c1 fa 0b 8b c2 c1 e8 1f 03 d0 69 c2 89 0e 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Strilix_C_2147744102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strilix.C!dha"
        threat_id = "2147744102"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strilix"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 65 72 76 69 63 65 4d 61 69 6e [0-8] 52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e}  //weight: 4, accuracy: Low
        $x_2_2 = "c:\\windows\\system32\\printhelp.dat" ascii //weight: 2
        $x_2_3 = "c:\\windows\\apphelp.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

