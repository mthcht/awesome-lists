rule TrojanDownloader_Win32_Injranluder_A_2147724282_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Injranluder.A"
        threat_id = "2147724282"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Injranluder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 5c 58 66 89 43 10 8d 43 12 6a 08 50 e8 ?? ?? ?? ?? 6a 2e 58 6a 65 59 6a 78}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 4d 08 06 6a 64 66 89 45 f6 58 66 89 45 fa 6a 6c}  //weight: 1, accuracy: High
        $x_1_3 = {74 11 8b 35 ?? ?? ?? ?? 53 57 ff d6 8d 45 d8 50 57 ff d6}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 51 14 85 c0 75 31 ff 75 ?? e8 ?? ?? ff ff 8b f8 85 ff 74}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 02 42 89 55 ?? 3c c3 75 f6 6a 00 6a 5c 8d 45 ?? 4a 50 53 ff 75 ?? 89 55 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {83 f8 66 7f 1a 74 ?? 83 f8 22 74 ?? 83 f8 2f 74 ?? 83 f8 5c 74 ?? 83 f8 62 74 ?? 6a fe eb ?? 83 e8 6e}  //weight: 1, accuracy: Low
        $x_1_7 = {81 f1 c8 47 5d 2e 3b c8 0f 94 c3 83 c7 04 3b c8 75 cc}  //weight: 1, accuracy: High
        $x_1_8 = {74 1f ff 75 10 ff 15 ?? ?? ?? ?? 85 c0 74 0b 68 b8 0b 00 00 ff 15 ?? ?? ?? ?? 53 57 e8 ?? ?? ff ff 56 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Injranluder_A_2147724453_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Injranluder.A!!Injranluder.gen!A"
        threat_id = "2147724453"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Injranluder"
        severity = "Critical"
        info = "Injranluder: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 5c 58 66 89 43 10 8d 43 12 6a 08 50 e8 ?? ?? ?? ?? 6a 2e 58 6a 65 59 6a 78}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 4d 08 06 6a 64 66 89 45 f6 58 66 89 45 fa 6a 6c}  //weight: 1, accuracy: High
        $x_1_3 = {74 11 8b 35 ?? ?? ?? ?? 53 57 ff d6 8d 45 d8 50 57 ff d6}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 51 14 85 c0 75 31 ff 75 ?? e8 ?? ?? ff ff 8b f8 85 ff 74}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 02 42 89 55 ?? 3c c3 75 f6 6a 00 6a 5c 8d 45 ?? 4a 50 53 ff 75 ?? 89 55 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {83 f8 66 7f 1a 74 ?? 83 f8 22 74 ?? 83 f8 2f 74 ?? 83 f8 5c 74 ?? 83 f8 62 74 ?? 6a fe eb ?? 83 e8 6e}  //weight: 1, accuracy: Low
        $x_1_7 = {81 f1 c8 47 5d 2e 3b c8 0f 94 c3 83 c7 04 3b c8 75 cc}  //weight: 1, accuracy: High
        $x_1_8 = {74 1f ff 75 10 ff 15 ?? ?? ?? ?? 85 c0 74 0b 68 b8 0b 00 00 ff 15 ?? ?? ?? ?? 53 57 e8 ?? ?? ff ff 56 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

