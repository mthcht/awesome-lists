rule TrojanDownloader_Win32_Zojectdow_STA_2147779320_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zojectdow.STA"
        threat_id = "2147779320"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zojectdow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 83 c0 01 89 45 f4 81 7d f4 ?? ?? ?? ?? 7d 19 8b 4d ec 03 4d f4 0f be 11 81 f2 ?? ?? ?? ?? 8b 45 ec 03 45 f4 88 10 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 00 00 00 00 00 00 00 [0-160] 63 65 72 74 2e 63 6f 6d 2f 44 69 67 69 43 65 72 74 41 73 73 75 72 65 64 49 44 52 6f 6f 74 43 41 2e 63 72 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zojectdow_STB_2147779377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zojectdow.STB"
        threat_id = "2147779377"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zojectdow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 83 c0 01 89 45 f4 81 7d f4 ?? ?? ?? ?? 7d ?? 8b 4d ec 03 4d f4 0f be 11 ?? f2 [0-4] 8b 45 ec 03 45 f4 88 10 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d f4 83 c1 01 89 4d f4 81 7d f4 ?? ?? ?? ?? 7d 1e 8b 55 f4 81 f2 ?? ?? ?? ?? 8b 45 ec 03 45 f4 0f be 08 33 ca 8b 55 ec 03 55 f4 88 0a eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f4 83 c0 01 89 45 f4 81 7d f4 ?? ?? ?? ?? 7d 1e 8b 4d f4 81 f1 ?? ?? ?? ?? 8b 55 ec 03 55 f4 0f be 02 33 c1 8b 4d ec 03 4d f4 88 01 eb}  //weight: 1, accuracy: Low
        $x_5_4 = {c6 00 2e 8b 4d ?? 83 c1 01 89 ?? ?? ?? ?? ?? c6 02 70 8b [0-16] c6 01 73 8b [0-16] c6 00 31}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zojectdow_STB_2147779377_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zojectdow.STB"
        threat_id = "2147779377"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zojectdow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 83 c0 01 89 45 f4 81 7d f4 ?? ?? ?? ?? 7d ?? 8b 4d ec 03 4d f4 0f be 11 ?? f2 [0-4] 8b 45 ec 03 45 f4 88 10 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d f4 83 c1 01 89 4d f4 81 7d f4 ?? ?? ?? ?? 7d 1e 8b 55 f4 81 f2 ?? ?? ?? ?? 8b 45 ec 03 45 f4 0f be 08 33 ca 8b 55 ec 03 55 f4 88 0a eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f4 83 c0 01 89 45 f4 81 7d f4 ?? ?? ?? ?? 7d 1e 8b 4d f4 81 f1 ?? ?? ?? ?? 8b 55 ec 03 55 f4 0f be 02 33 c1 8b 4d ec 03 4d f4 88 01 eb}  //weight: 1, accuracy: Low
        $x_5_4 = {c6 02 2e 8b 45 ?? 83 c0 01 89 ?? ?? ?? ?? ?? c6 01 70 8b [0-16] c6 00 73 8b [0-16] c6 02 31}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

