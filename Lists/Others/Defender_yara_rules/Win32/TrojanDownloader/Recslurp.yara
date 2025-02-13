rule TrojanDownloader_Win32_Recslurp_A_2147660048_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Recslurp.A"
        threat_id = "2147660048"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Recslurp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 3b 8b 55 0c 0f be 14 32 31 d0 83 c0 20}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc 8b 50 3c 03 56 54 52 50 ff 75 f8 e8}  //weight: 1, accuracy: High
        $x_1_3 = {c6 06 aa 6a 00 6a 01 56 ff 75 f4 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 06 bb}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 3b 89 d8 40 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Recslurp_B_2147687996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Recslurp.B"
        threat_id = "2147687996"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Recslurp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e8 10 66 31 44 24 ?? 33 c9 33 c0 8a 54 05 ?? 30 54 0c ?? 40 83 f8 04 75 02 33 c0 41 83 f9 08 72 ea}  //weight: 2, accuracy: Low
        $x_2_2 = {76 21 8b 54 24 ?? 0f b6 14 11 33 d0 81 e2 ff 00 00 00 c1 e8 08 33 04 95 ?? ?? ?? ?? 41 3b 4c 24 ?? 72 df}  //weight: 2, accuracy: Low
        $x_1_3 = "\\Microsoft\\Shared Police" wide //weight: 1
        $x_1_4 = "MachineParamCPUU" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Recslurp_B_2147687996_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Recslurp.B"
        threat_id = "2147687996"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Recslurp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7a 05 a8 74 1f 3c ac 75 0d 8a 4a 05 80 f9 0f}  //weight: 1, accuracy: High
        $x_1_2 = {8a 45 0a 30 44 24 12 30 44 24 16 8a d1 30 54 24 17}  //weight: 1, accuracy: High
        $x_1_3 = {81 c7 ff ff 00 00 66 81 ff 9e 25 89 7c 24 18}  //weight: 1, accuracy: High
        $x_1_4 = "\\Microsoft\\Shared Police" wide //weight: 1
        $x_1_5 = {25 00 73 00 25 00 30 00 38 00 78 00 2e 00 25 00 73 00 00 00 74 00 6d 00 70 00 00 00 25 00 73 00 25 00 30 00 38 00 78 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 52 00 75 00 6e 00 00 00 25 00 73 00 3a 00 2a 00 3a 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 3a 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_7 = "S:(ML;;NRNWNX;;;LW)" wide //weight: 1
        $x_1_8 = {53 56 b8 42 23 00 00 ba ?? ?? ?? ?? 33 db e8 ?? ?? ?? ?? 8b f0 83 fe ff 75 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_Win32_Recslurp_F_2147720586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Recslurp.F"
        threat_id = "2147720586"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Recslurp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "46.148.22.10" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Shared Police" ascii //weight: 1
        $x_1_3 = "MachineParam" ascii //weight: 1
        $x_1_4 = "smtp.gmail.com" ascii //weight: 1
        $x_1_5 = "plus.smtp.mail.yahoo.com" ascii //weight: 1
        $x_1_6 = "S:(ML;;NRNWNX;;;LW)" ascii //weight: 1
        $x_1_7 = {9f 25 00 00 66}  //weight: 1, accuracy: High
        $x_1_8 = {9e 25 00 00 66}  //weight: 1, accuracy: High
        $x_1_9 = {8a 54 31 ff 30 14 31 49 75 f6 33 c9 85 c0 76 09 80 04 31}  //weight: 1, accuracy: High
        $x_1_10 = {b8 22 15 3c 74}  //weight: 1, accuracy: High
        $x_1_11 = {b8 14 93 93 84}  //weight: 1, accuracy: High
        $x_1_12 = {33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff}  //weight: 1, accuracy: High
        $x_2_13 = {05 a8 74 20 ?? ?? ac 75 0b ?? ?? 05 ?? 0f}  //weight: 2, accuracy: Low
        $x_2_14 = {0f b6 45 eb 33 ff 48 0f 84 ?? ?? 00 00 48 48 74 ?? 48 0f 85}  //weight: 2, accuracy: Low
        $x_1_15 = {c6 45 f7 5a}  //weight: 1, accuracy: High
        $x_1_16 = {80 7d f7 5a}  //weight: 1, accuracy: High
        $x_1_17 = {c6 45 f7 5b}  //weight: 1, accuracy: High
        $x_2_18 = {8b 07 81 c6 30 75 00 00 85 c0 74 3c 6b c0 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Recslurp_F_2147720587_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Recslurp.F!!Recslurp.gen!A"
        threat_id = "2147720587"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Recslurp"
        severity = "Critical"
        info = "Recslurp: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Microsoft\\Shared Police" ascii //weight: 1
        $x_1_2 = "MachineParam" ascii //weight: 1
        $x_1_3 = "smtp.gmail.com" ascii //weight: 1
        $x_1_4 = "plus.smtp.mail.yahoo.com" ascii //weight: 1
        $x_1_5 = "S:(ML;;NRNWNX;;;LW)" ascii //weight: 1
        $x_1_6 = {9f 25 00 00 66}  //weight: 1, accuracy: High
        $x_1_7 = {9e 25 00 00 66}  //weight: 1, accuracy: High
        $x_1_8 = {8a 54 31 ff 30 14 31 49 75 f6 33 c9 85 c0 76 09 80 04 31}  //weight: 1, accuracy: High
        $x_1_9 = {b8 22 15 3c 74}  //weight: 1, accuracy: High
        $x_1_10 = {b8 14 93 93 84}  //weight: 1, accuracy: High
        $x_1_11 = {33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff}  //weight: 1, accuracy: High
        $x_2_12 = {05 a8 74 20 ?? ?? ac 75 0b ?? ?? 05 ?? 0f}  //weight: 2, accuracy: Low
        $x_2_13 = {0f b6 45 eb 33 ff 48 0f 84 ?? ?? 00 00 48 48 74 ?? 48 0f 85}  //weight: 2, accuracy: Low
        $x_1_14 = {c6 45 f7 5a}  //weight: 1, accuracy: High
        $x_1_15 = {80 7d f7 5a}  //weight: 1, accuracy: High
        $x_1_16 = {c6 45 f7 5b}  //weight: 1, accuracy: High
        $x_2_17 = {8b 07 81 c6 30 75 00 00 85 c0 74 3c 6b c0 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

