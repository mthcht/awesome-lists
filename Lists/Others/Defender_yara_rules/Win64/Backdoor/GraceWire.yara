rule Backdoor_Win64_GraceWire_I_2147744269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/GraceWire.I!dha"
        threat_id = "2147744269"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "GraceWire"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 fd 42 72 b6 48 89 b4 24 e0 00 00 00 48 89 bc 24 b8 00 00 00 4c 89 a4 24 b0 00 00 00 4c 89 b4 24 a8 00 00 00 89 bc 24 a0 00 00 00 e8 ?? 01 00 00 b9 c1 6d 68 ed 48 8b d8 e8 ?? 01 00 00 b9 21 3b df 50 48 8b f8 e8 ?? 01 00 b9 91 fd 47 59 48 8b f0 e8 ?? 01 00 00 b9 7f 28 a0 69 4c 8b e0 e8 ?? 01 00 00 b9 2f 44 d4 9b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_GraceWire_K_2147896983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/GraceWire.K!!GraceWire.K"
        threat_id = "2147896983"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "GraceWire"
        severity = "Critical"
        info = "GraceWire: an internal category used to refer to some threats"
        info = "K: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 00 00 00 00 00 00 43 00 3a 00 5c 00 64 00 62 00 67 00 73 00 74 00 61 00 74 00 65 00 5c 00 25 00 64 00 2d 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {3f 41 56 57 69 72 65 43 6c 65 61 6e 75 70 54 68 72 65 61 64 40 53 65 73 73 69 6f 6e 47 65 6e 65 72 69 63 40 4e 53 40 40 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {3f 41 56 57 69 72 65 43 6c 69 65 6e 74 43 6f 6e 6e 65 63 74 69 6f 6e 54 68 72 65 61 64 40 4e 53 40 40 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

