rule TrojanDropper_Win32_RedLeaves_A_2147723371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/RedLeaves.A!dha"
        threat_id = "2147723371"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLeaves"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 0c 3a 83 c2 02 88 0e 83 fa 08 7c ?? eb ?? ba 08 00 00 00 32 0c 3a 83 c2 02 88 0e 83 fa 10}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_RedLeaves_B_2147723450_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/RedLeaves.B!dha"
        threat_id = "2147723450"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLeaves"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 40 ff b5 ?? ?? ff ff 53 ff 15 ?? ?? ?? 10 57 e8 ?? ?? 00 00 83 c4 04 6a 00 6a 00 6a 00 53 6a 00 6a 00 ff 15 ?? ?? ?? 10 50 ff 15 ?? ?? ?? 10 68 98 08 00 00 ff 15 ?? ?? ?? 10}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 cd cc cc cc 8b ce f7 e6 c1 ea 03 8d 04 92 03 c0 2b c8 8a 44 0d ?? 2a 44 0d ?? 00 04 1e 46 3b f7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_RedLeaves_C_2147730370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/RedLeaves.C!dha"
        threat_id = "2147730370"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLeaves"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Data ERROR!!!     Please check your input!" ascii //weight: 1
        $x_1_2 = {45 58 49 54 3f 00 00 00 cd cb b3 f6 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {55 8b ec 8b 55 0c 33 c0 85 d2 7e 0d 8b 4d 08 90 80 34 08 ?? 40 3b c2 7c f7 33 c0 5d c2 08 00}  //weight: 1, accuracy: Low
        $x_1_4 = {33 db 39 58 f4 0f 95 c3 89 18 33 db 39 58 08 0f 95 c3 89 58 14 33 db 39 58 1c 0f 95 c3 83 c0 3c 2b d1 89 58 ec 75 d9 89 95 d8 f5 ff ff 8d 9d 68 f8 ff ff}  //weight: 1, accuracy: High
        $x_1_5 = {43 89 9d cc f5 ff ff 89 18 83 c9 ff 83 38 09 7f 1a 8b 95 d8 f5 ff ff 41 83 f9 51 7c 99 8b 85 d0 f5 ff ff 8b 9d d4 f5 ff ff eb 1b 8b 9d d4 f5 ff ff c7 00 00 00 00 00 8b 85 d0 f5 ff ff 8b 10 4a 83 eb 02 83 e8 08 83 fb ff 7c 18 b9 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_RedLeaves_D_2147730371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/RedLeaves.D!dha"
        threat_id = "2147730371"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLeaves"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 44 6c 67 43 68 75 50 65 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {d7 e3 b2 ca b7 d6 ce f6 b9 a4 be df 20 56 31 2e 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6c 76 65 73 6e 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 62 77 69 64 2e 73 75 77 00}  //weight: 1, accuracy: High
        $x_1_5 = {64 65 6e 74 79 6f 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {75 6e 69 74 65 73 2e 74 75 63 00}  //weight: 1, accuracy: High
        $x_1_7 = {43 44 6c 67 44 72 61 77 65 72 00}  //weight: 1, accuracy: High
        $x_2_8 = {8b 45 0c 56 89 46 38 89 5e 3c e8 f5 0a 00 00 88 46 40 39 5e 38 75 1c 8b 46 0c 83 c8 04 83 c8 04 83 e0 17 89 46 0c 85 46 10 74 08 53 8b ce e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_9 = {99 b9 1a 00 00 00 f7 f9 80 c2 41 88 94 35 ?? ?? ?? ?? 03 f7 81 fe 96 00 00 00 7c [0-76] 83 c8 02 39 59 38 75 26 83 c8 04 eb 21 8b ?? ?? ?? ?? ?? 8b ?? 04 8b 84 0d ?? ?? ?? ?? 8d 8c 0d ?? ?? ?? ?? f7 d8 1b c0 83 e0 fc 83 c0 04 83 e0 17}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

