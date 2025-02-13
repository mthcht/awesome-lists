rule TrojanDownloader_Win32_PterodoGen_A_2147811395_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PterodoGen.A!dha"
        threat_id = "2147811395"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PterodoGen"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 7d d0 01 0f 85 ?? ?? ?? ?? 81 7d ?? aa 00 00 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f9 01 74 ?? 33 c0 eb ?? 8b 55 08 81 7a 08 aa 00 00 00 74}  //weight: 1, accuracy: Low
        $x_1_3 = {66 83 7c 24 14 01 0f 85 ?? ?? ?? ?? 81 7c ?? ?? aa 00 00 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_PterodoGen_B_2147811396_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PterodoGen.B!dha"
        threat_id = "2147811396"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PterodoGen"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 52 04 88 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74 21 b8 cd cc cc cc f7 ?? 8b ?? c1 ea 03 8d 0c 92 03 c9 2b c1 8a 80 ?? ?? ?? ?? 30 04 ?? ?? 3b ?? 72 df}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 52 04 88 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74 21 b8 cd cc cc cc f7 ?? 8b ?? c1 ea 03 8d 0c 92 03 c9 2b c1 8a 80 ?? ?? ?? ?? 30 04 ?? ?? 3b ?? 72 df}  //weight: 1, accuracy: Low
        $x_1_3 = {2b fe be 00 00 00 00 74 21 b8 cd cc cc cc f7 ?? 8b ?? c1 ea 03 8d 0c 92 03 c9 2b c1 8a 80 ?? ?? ?? ?? 30 04 ?? ?? 3b ?? 72 df}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 f8 00 00 00 00 c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 24 8b 55 08 03 55 fc 0f b6 0a 8b 45 fc 33 d2 f7 75 14 8b 45 10 0f b6 14 10 33 ca 8b 45 08 03 45 fc 88 08 eb cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_PterodoGen_C_2147811397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PterodoGen.C!dha"
        threat_id = "2147811397"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PterodoGen"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 45 fc 8b 4d 08 0f be 0c 01 0f b7 45 fc 0f b7 55 18 03 c2 0f b7 75 14 99 f7 fe 8b 45 10 0f be 14 10 33 ca 0f b7 45 fc 8b 55 f8 88 0c 02 eb ba}  //weight: 1, accuracy: High
        $x_1_2 = {8b 04 24 89 d1 31 d2 01 d8 f7 f6 8b 44 24 20 0f b6 04 10 89 ca 8b 4c 24 18 32 04 19 88 44 1d 00 0f b7 df 47 39 d3 72 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

