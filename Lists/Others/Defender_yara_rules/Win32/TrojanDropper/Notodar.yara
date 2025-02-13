rule TrojanDropper_Win32_Notodar_A_2147690097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Notodar.A"
        threat_id = "2147690097"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Notodar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\%s\\rundll32.exe \"%s\" update" wide //weight: 1
        $x_1_2 = {8b 4d 7c 83 c4 14 6a 0a 6a 1e 58 8d 7d dc e8 ?? ?? ?? ?? 53 8b c7 50 68 02 00 00 80 e8 ?? ?? ?? ?? 8b f8 3b fe 75 11 53 8d 45 dc 50 68 01 00 00 80 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {53 56 57 89 45 dc bb e5 55 9a 15 bf b5 3b 12 1f be 33 13 49 05 6a 01 83}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 00 00 08 89 45 f0 6a 40 8d 45 f0 50 8d 45 d8 50 68 1f 00 0f 00 8d 45 f8 50 c7 45 d8 18 00 00 00 89 7d dc c7 45 e4 02 00 00 00 89 7d e0 89 7d e8 89 7d ec 89 7d f4 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Notodar_A_2147690828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Notodar.A!!Notodar.gen!D"
        threat_id = "2147690828"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Notodar"
        severity = "Critical"
        info = "Notodar: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\%s\\rundll32.exe \"%s\" update" wide //weight: 1
        $x_1_2 = {8b 4d 7c 83 c4 14 6a 0a 6a 1e 58 8d 7d dc e8 ?? ?? ?? ?? 53 8b c7 50 68 02 00 00 80 e8 ?? ?? ?? ?? 8b f8 3b fe 75 11 53 8d 45 dc 50 68 01 00 00 80 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {53 56 57 89 45 dc bb e5 55 9a 15 bf b5 3b 12 1f be 33 13 49 05 6a 01 83}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 00 00 08 89 45 f0 6a 40 8d 45 f0 50 8d 45 d8 50 68 1f 00 0f 00 8d 45 f8 50 c7 45 d8 18 00 00 00 89 7d dc c7 45 e4 02 00 00 00 89 7d e0 89 7d e8 89 7d ec 89 7d f4 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

