rule TrojanDownloader_Win32_Perkesh_A_2147616777_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Perkesh.gen!A"
        threat_id = "2147616777"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Perkesh"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 10 8a 14 0e 80 f2 ?? f6 d2 88 14 0e 46 3b f0 72 f0}  //weight: 2, accuracy: Low
        $x_2_2 = {c6 40 ff 74 c6 40 fe 78 c6 40 fd 74}  //weight: 2, accuracy: High
        $x_1_3 = {68 20 24 08 00 ff 75 08 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {83 c7 04 8b 07 3b c6 75 c2 68 e8 03 00 00 ff 55 f4 eb a7}  //weight: 1, accuracy: High
        $x_1_5 = {44 6f 77 6e 44 6c 6c 2e 64 6c 6c 00 53 65 72 76}  //weight: 1, accuracy: High
        $x_2_6 = {81 7d 0c 01 04 00 00 74 ?? 81 7d 0c 00 04 00 00 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] b8 22 00 00 c0}  //weight: 2, accuracy: Low
        $x_1_7 = {81 e9 18 24 08 00 0f 84 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 e9 e0 ff 19 00}  //weight: 1, accuracy: Low
        $x_3_8 = {40 83 f8 09 72 ef 0b 00 8a 4c 05 ?? 80 f1 ?? 88 4c 05}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Perkesh_E_2147618455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Perkesh.E"
        threat_id = "2147618455"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Perkesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {51 56 56 6a 0b ff d0 3b c6 0f 84 ?? ?? ?? ?? 3d 04 00 00 c0}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 00 6a 40 ff 15 ?? ?? ?? ?? 85 c0 89 45 fc 74 1f 6a 01 6a 00 8d 4d fc 68 ff 0f 1f 00 51 6a ff 50 6a ff ff d7 6a 00 ff 75 fc ff 15}  //weight: 5, accuracy: Low
        $x_5_3 = "PsSetLoadImageNotifyRoutine" ascii //weight: 5
        $x_5_4 = "ZwSystemDebugControl" ascii //weight: 5
        $x_5_5 = "ZwQuerySystemInformation" ascii //weight: 5
        $x_5_6 = "ZwDuplicateObject" ascii //weight: 5
        $x_2_7 = {55 68 1c 00 22 00 57 ff 15}  //weight: 2, accuracy: High
        $x_2_8 = {68 a0 bb 0d 00 ff 15}  //weight: 2, accuracy: High
        $x_2_9 = {68 20 bf 02 00 ff 15}  //weight: 2, accuracy: High
        $x_1_10 = "KAV32.exe" ascii //weight: 1
        $x_1_11 = "360Safe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Perkesh_F_2147627994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Perkesh.F"
        threat_id = "2147627994"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Perkesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 35 55 bd ?? ?? ?? ?? 6a 01 e8 ?? ?? ?? ?? 6a 00 55 55 6a ff e8 ?? ?? ?? ?? 8a c3 b1 ?? 2c ?? 8b fe f6 e9 00 04 33}  //weight: 2, accuracy: Low
        $x_2_2 = {68 78 e6 00 00 e8 ?? ?? ?? ?? 46 3b 35 ?? ?? ?? ?? 7c ed eb 10 6a 1e}  //weight: 2, accuracy: Low
        $x_1_3 = {26 7a 3d 00 26 74 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {7e 25 78 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00 00 25 73 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Perkesh_G_2147628593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Perkesh.G"
        threat_id = "2147628593"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Perkesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 04 32 33 c0 42 f2 ae f7 d1 49 3b d1 72 e6}  //weight: 2, accuracy: High
        $x_2_2 = {8a c3 b1 03 2c ?? 8b fe f6 e9 00 04 33}  //weight: 2, accuracy: Low
        $x_1_3 = {74 11 68 e0 2e 00 00 ff 15 00 10 40 00 46 3b 75 10 7c d7}  //weight: 1, accuracy: High
        $x_1_4 = {6a 1e 5e 68 78 e6 00 00 ff 15 00 10 40 00 4e 75 f2}  //weight: 1, accuracy: High
        $x_1_5 = {3d 3d 22 00 00 7d 1c 33 f6 85 c0 7e 27}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

