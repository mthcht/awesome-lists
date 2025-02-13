rule Trojan_Win64_Solorigate_SB_2147771447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Solorigate.SB!dha"
        threat_id = "2147771447"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Solorigate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c2 c0 e0 02 8d 0c 10 02 c9 44 2a ?? 41 80 ?? 30 46 88 [0-3] 41 ff ?? 4c 8b [0-2] 83 fa 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b 0b 48 8d 5b 04 41 8b c1 48 c1 e8 10 0f b6 c8 41 8b c1 48 c1 e8 08}  //weight: 1, accuracy: High
        $x_2_3 = {48 8b cb 80 31 ?? 48 ff c1 48 8b 95 c0 00 00 00 48 8b c1 48 2b c3 48 3b c2 72 e8}  //weight: 2, accuracy: Low
        $x_2_4 = {b8 89 88 88 88 f7 ef c7 44 ?? ?? 00 00 00 01 4d 8b cc 03 d7}  //weight: 2, accuracy: Low
        $x_2_5 = {37 2d 7a 69 70 2e 64 6c 6c 00 44 6c 6c [0-96] 2e 54 6b 53 65 6c 50 72 6f 70 50 72 6f 63}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Solorigate_SC_2147772527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Solorigate.SC!dha"
        threat_id = "2147772527"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Solorigate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 80 0f b6 03 03 c9 32 c1 0f b6 c0 66 0f 6e c0 f3 0f e6 c0 f2 0f 5e c6 f2 0f 2c c0 88 03 e8 ?? ?? ?? ?? 6b c8 ?? ff c7 00 0b e8 ?? ?? ?? ?? 8d 0c 80 c1 e1 02 3b f9 7c c1}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b c0 48 8d 5b 01 b8 ?? ?? ?? ?? 41 f7 e8 41 03 d0 c1 fa 06 8b ca c1 e9 1f 03 d1 6b ca ?? 44 2b c1 41 83 c0 02 44 00 43 ff 48 83 ef 01 75 ?? ?? ?? ?? ?? ?? ?? 8d 8e ?? ?? 00 00 2b c8 85 c9 7f ac}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

