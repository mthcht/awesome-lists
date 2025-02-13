rule TrojanDownloader_Win32_GhostRAT_A_2147893272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GhostRAT.A!MTB"
        threat_id = "2147893272"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 7d e8 10 8b 45 d4 73 ?? 8d 45 d4 8b 8c b5 78 fd ff ff 51 50 ff 15 ?? ?? ?? ?? 83 c4 08 85 c0 74 ?? 46 83 fe 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_GhostRAT_B_2147893423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GhostRAT.B!MTB"
        threat_id = "2147893423"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 c8 31 d2 f7 f6 8b 45 ?? 8a 04 10 30 04 0b 41}  //weight: 2, accuracy: Low
        $x_2_2 = {89 f0 31 d2 f7 f1 8b 45 ?? 8a 04 10 30 04 33 46}  //weight: 2, accuracy: Low
        $x_2_3 = {f7 f6 8b 45 ?? 01 d0 0f b6 00 31 d8 88 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_GhostRAT_C_2147894658_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GhostRAT.C!MTB"
        threat_id = "2147894658"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c7 0f 43 4c 24 ?? 99 f7 7c 24 ?? 8a 04 0a 30 04 37 47 3b 7c 24}  //weight: 2, accuracy: Low
        $x_2_2 = {8b f8 6a 01 ff d6 6a 01 ff d6 6a 01 ff d6 6a 01 ff d6 6a 01}  //weight: 2, accuracy: High
        $x_2_3 = {0f be 10 8b 45 ?? 03 45 fc 0f b6 08 33 ca 8b 55 ?? 03 55 fc 88 0a}  //weight: 2, accuracy: Low
        $x_2_4 = {89 45 8c 6a 01 ff 15 00 00 41 00 6a 01 ff 15 00 00 41 00 6a 01 ff 15 00 00 41 00 6a 01 ff 15 00 00 41}  //weight: 2, accuracy: High
        $x_2_5 = {89 c8 99 f7 3e 0f b6 04 13 30 04 0f 8d 41 ?? 99 f7 3e 0f b6 04 13 30 44 0f}  //weight: 2, accuracy: Low
        $x_2_6 = {89 c8 99 f7 7e ?? 0f b6 04 13 30 04 0f 8d 41 ?? 99 f7 7e ?? 0f b6 04 13 30 44 0f}  //weight: 2, accuracy: Low
        $x_2_7 = {89 c7 6a 01 ff d3 6a 01 ff d3 6a 01 ff d3 6a 01 ff d3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_GhostRAT_E_2147894662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GhostRAT.E!MTB"
        threat_id = "2147894662"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 0c 8d 85 f8 fe ff ff 57 50 56 ff 15 ?? ?? ?? ?? 8d 45 fc 50 68 3f 00 0f 00 56 68 ?? ?? ?? ?? 68 01 00 00 80 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {57 8d 85 f8 fe ff ff 50 6a 01 56 68 ?? ?? ?? ?? ff 75 fc ff 15 ?? ?? ?? ?? ff 75 fc ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = {83 c4 0c 8d 85 f8 fe ff ff 68 04 01 00 00 50 6a 00 ff 15 ?? ?? ?? ?? 8d 45 fc 50 68 3f 00 0f 00 6a 00 68 ?? ?? ?? ?? 68 01 00 00 80 ff 15}  //weight: 2, accuracy: Low
        $x_2_4 = {68 04 01 00 00 8d 85 f8 fe ff ff 50 6a 01 6a 00 68 ?? ?? ?? ?? ff 75 fc ff 15 ?? ?? ?? ?? ff 75 fc ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_GhostRAT_F_2147895852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GhostRAT.F!MTB"
        threat_id = "2147895852"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 24 50 ff 15 ?? ?? 40 00 8b 4c 24 28 8b ?? 51 66 c7 44 24 14 02 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_GhostRAT_G_2147896129_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GhostRAT.G!MTB"
        threat_id = "2147896129"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 8b f8 66 c7 44 24 14 02 00 e8 ?? ?? 00 00 66 89 44 24 12 8b 47 0c 6a 10 8b 08 8d 44 24 14 50 8b 11 8b 4e 08 51 89 54 24 20 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {8b f0 66 a1 64 a1 40 00 50 66 c7 44 24 18 02 00 e8 ?? ?? 00 00 66 89 44 24 16 8b 4e 0c 6a 10 8b 11 8d 4c 24 18 51 8b 02 8b 15 f0 ea 40 00 52 89 44 24 24 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_GhostRAT_I_2147896724_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GhostRAT.I!MTB"
        threat_id = "2147896724"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 44 50 ff 15 ?? ?? 41 00 53 8b f8 66 c7 44 24 34 02 00 ff 15 ?? ?? 41 00 66 89 44 24 32 8b 4f 0c 6a 10 8b 11 8d 4c 24 34 51 8b 02 8b 56 08 52 89 44 24 40 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {c6 44 24 28 4b c6 44 24 2a 52 c6 44 24 2b 4e c6 44 24 2d 4c c6 44 24 2e 33 c6 44 24 2f 32 c6 44 24 30 2e c6 44 24 31 64}  //weight: 2, accuracy: High
        $x_2_3 = {c6 44 24 14 4b c6 44 24 16 52 c6 44 24 17 4e c6 44 24 19 4c c6 44 24 1a 33 c6 44 24 1b 32 c6 44 24 1c 2e c6 44 24 1d 64}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_GhostRAT_H_2147897138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GhostRAT.H!MTB"
        threat_id = "2147897138"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4c 24 28 8b f8 51 66 c7 44 24 14 02 00 ff 15 ?? ?? 41 00 66 89 44 24 12 8b ?? 0c 6a 10 8b 02 8d 54 24 14 52 8b 08 8b 46 08 50 89 4c 24 20 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {53 8b f8 66 c7 44 24 14 02 00 ff ?? ?? 78 41 00 66 89 44 24 12 8b ?? 0c 6a 10 8b 08 8d 44 24 14 50 8b 11 8b 4e 08 51 89 54 24 20 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

