rule Trojan_Win64_Foosace_K_2147705793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Foosace.K!dha"
        threat_id = "2147705793"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b9 22 2c 20 49 6e 69 74 57 48 89 4c 38 0e 66 c7 44 38 16 20 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 b8 33 32 2e 45 58 45 20 22 48 89 85 ?? ?? ?? ?? 48 b8 52 55 4e 44 4c 4c 33 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Foosace_K_2147705793_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Foosace.K!dha"
        threat_id = "2147705793"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 6e 69 74 57 00 52 65 67 69 73 74 65 72 4e 65 77 43 6f 6d 6d 61 6e 64 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74}  //weight: 2, accuracy: High
        $x_1_2 = {41 b8 06 00 00 00 41 f7 f0 8b c2 8b c0 48 8b 54 24 ?? 0f b6 04 02 33 c8}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 f4 ee ee ee eb 14 44 8b 44 24 ?? 48 8b 54 24 ?? 48 8b 4c 24 ?? e8 ?? ?? ?? ?? 48 83 c4 38 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Foosace_K_2147705793_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Foosace.K!dha"
        threat_id = "2147705793"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 c7 44 c8 08 10 00 00 00 8b ca 48 03 c9 ff c2 48 8d 05 ?? ?? ?? ?? 49 89 04 c8 41 c7 44 c8 08 15 00 00 00 8b ca 48 03 c9 ff c2}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 81 28 02 00 00 48 85 c0 0f 84 ?? 00 00 00 48 8b 0d ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 48 89 81 00 03 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {78 02 00 00 33 d2 44 8b c0 48 8b 05 ?? ?? ?? ?? 8d 4a 01 ff 90 10 02 00 00 02 00 ff 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

