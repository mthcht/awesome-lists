rule TrojanDownloader_Win32_Tofsee_A_2147679403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tofsee.gen!A"
        threat_id = "2147679403"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 40 01 6a 70 c6 40 03 67 eb}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 06 32 55 14 88 10 8a d1 02 55 18 f6 d9 00 55 14 40 4f 75 ea}  //weight: 1, accuracy: High
        $x_1_3 = {57 83 c3 03 6a 3a 53 e8 ?? ?? ?? ?? 8b f8 59 59 85 ff 74 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Tofsee_D_2147680398_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tofsee.D"
        threat_id = "2147680398"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 0c ff 75 08 6a 50 50 e8 ?? ?? ?? ?? 8b f8 83 c4 40 85 ff 75 11 68 60 ea 00 00 43 ff 15 ?? ?? ?? ?? 3b 5d 18 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {3b c3 74 0e c6 40 01 6a c6 40 02 70 c6 40 03 67 eb ?? 8d 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

