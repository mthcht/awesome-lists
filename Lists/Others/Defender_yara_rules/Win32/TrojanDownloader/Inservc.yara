rule TrojanDownloader_Win32_Inservc_A_2147601828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Inservc.A"
        threat_id = "2147601828"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Inservc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "lists.xmirror.us" ascii //weight: 1
        $x_1_2 = "ddl-help.info" ascii //weight: 1
        $x_1_3 = {7e f0 83 c4 f8 6a 00 6a 00 ff 75 14 8b b5 ?? ?? ff ff 56 8b 85 ?? ?? ff ff 50 6a 00 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {7e f0 83 c4 f8 8b b5 ?? ?? ff ff 56 8b 85 ?? ?? ff ff 50 e8 ?? ?? 00 00 83 c4 08 85 c0 75 17 83 c4 f4 6a 50 e8 ?? ?? 00 00 66 89 ?? ?? ?? ff ff 83 c4 0c eb 0c}  //weight: 1, accuracy: Low
        $x_1_5 = {7e f0 83 c4 f8 8b 95 ?? ?? ff ff 52 53 e8 ?? ?? 00 00 89 c2 83 c4 10 85 d2 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Inservc_A_2147602387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Inservc.gen!A"
        threat_id = "2147602387"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Inservc"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 [0-32] 57 53 41 43 6c 65 61 6e 75 70 00 00 00 00 1f 00 57 53 41 53 74 61 72 74 75 70 00 00 00 00 25 00 63 6c 6f 73 65 73 6f 63 6b 65 74 00 00 00 26 00 63 6f 6e 6e 65 63 74 00 00 00 28 00 67 65 74 68 6f 73 74 62 79 61 64 64 72 00 29 00 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 00 2f 00 67 65 74 73 65 72 76 62 79 6e 61 6d 65 00 34 00 68 74 6f 6e 73 00 35 00 69 6e 65 74 5f 61 64 64 72 00 3d 00 72 65 63 76 00 00 43 00 73 65 6e 64 00 00 48 00 73 6f 63 6b 65 74 00}  //weight: 10, accuracy: Low
        $x_10_2 = {89 c2 83 c4 f4 c1 e0 05 29 d0 8d 04 82 c1 e0 03 50 e8 ?? ?? 00 00 83 c4 1c eb}  //weight: 10, accuracy: Low
        $x_10_3 = {83 c4 fc 6a 06 6a 01 6a 02 e8 ?? ?? 00 00 89 85 ?? ?? ff ff 83 c4 04 83 f8 ff 0f 84 ?? ?? 00 00}  //weight: 10, accuracy: Low
        $x_10_4 = {25 73 5c 25 73 25 64 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_5 = {6f 70 65 6e 00}  //weight: 10, accuracy: High
        $x_1_6 = "User-Agent: Mozilla/4.0 (compatible;" ascii //weight: 1
        $x_1_7 = {74 63 70 00 68 74 74 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

