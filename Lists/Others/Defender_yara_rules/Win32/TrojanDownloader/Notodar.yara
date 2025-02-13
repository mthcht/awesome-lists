rule TrojanDownloader_Win32_Notodar_A_2147689227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Notodar.A"
        threat_id = "2147689227"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Notodar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 72 6c 23 25 64 00 00 64 61 74 61 00 00 00 00 70 6b 00 00 63 66 67 00 77 65 76 74 61 70 69 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {3b c3 75 16 ff 74 24 18 8b 44 24 28 e8 49 fc ff ff ff 74 24 24 e8 ?? ?? ?? ?? ff 74 24 1c e8}  //weight: 1, accuracy: Low
        $x_1_3 = {2d f3 f2 2f 2f 50 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 08 89 44 24 24 ff 15 ?? ?? ?? ?? 85 c0 74 15 50 ff 75 08 8d 44 24 1c 50 8d 44 24 34 50}  //weight: 1, accuracy: Low
        $x_1_4 = {39 5c 24 20 75 07 68 ?? ?? ?? ?? eb 05 68 80 ee 36 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {eb 09 8b f3 8b 1b e8 ?? ?? ?? ?? 3b df 75 f3 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {8b f0 85 f6 74 12 56 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 2b f7 59 03 c6 ff d0 5f 33 c0 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Notodar_A_2147689579_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Notodar.A!!Notodar.gen!A"
        threat_id = "2147689579"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Notodar"
        severity = "Critical"
        info = "Notodar: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 72 6c 23 25 64 00 00 64 61 74 61 00 00 00 00 70 6b 00 00 63 66 67 00 77 65 76 74 61 70 69 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {3b c3 75 16 ff 74 24 18 8b 44 24 28 e8 49 fc ff ff ff 74 24 24 e8 ?? ?? ?? ?? ff 74 24 1c e8}  //weight: 1, accuracy: Low
        $x_1_3 = {2d f3 f2 2f 2f 50 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 08 89 44 24 24 ff 15 ?? ?? ?? ?? 85 c0 74 15 50 ff 75 08 8d 44 24 1c 50 8d 44 24 34 50}  //weight: 1, accuracy: Low
        $x_1_4 = {39 5c 24 20 75 07 68 ?? ?? ?? ?? eb 05 68 80 ee 36 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {eb 09 8b f3 8b 1b e8 ?? ?? ?? ?? 3b df 75 f3 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {8b f0 85 f6 74 12 56 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 2b f7 59 03 c6 ff d0 5f 33 c0 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

