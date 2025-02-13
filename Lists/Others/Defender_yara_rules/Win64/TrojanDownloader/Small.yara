rule TrojanDownloader_Win64_Small_PABO_2147894066_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Small.PABO!MTB"
        threat_id = "2147894066"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 4f ec c4 4e f7 ee c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 34 40 0f b6 c6 2a c1 04 39 41 30 00 ff c6 4d 8d 40 01 83 fe 26}  //weight: 1, accuracy: High
        $x_1_2 = {b8 4f ec c4 4e 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 34 41 0f b6 c0 2a c1 04 39 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Small_PADA_2147900955_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Small.PADA!MTB"
        threat_id = "2147900955"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 41 0f 6e d0 66 0f 70 d2 00 66 0f fe d5 66 0f 6f ca 66 0f 62 ca 66 0f 38 28 cc 66 0f 6f c2 66 0f 6a c2 66 0f 38 28 c4 0f c6 c8 dd 66 0f e2 ce 66 0f 6f c1 66 41 0f d2 c0 66 0f fe c1 66 0f 38 40 c7 66 0f fa d0 f2 0f 70 c2 d8 f3 0f 70 c8 d8 66 0f 70 d1 d8 0f 54 15 c3 d8 07 00 66 0f 67 d2 66 0f 6e c2 66 0f fc d0 66 0f 6e 41 fc 0f 57 d0 66 0f 7e 51 fc}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f 6f c1 66 41 0f d2 c0 66 0f fe c1 66 0f 38 40 c7 66 0f fa d8 f2 0f 70 c3 d8 f3 0f 70 c8 d8 66 0f 70 d1 d8 0f 54 15 4b d8 07 00 66 0f 67 d2 66 0f 6e c2 66 0f fc d0 66 0f 6e 01 0f 57 d0 66 0f 7e 11 41 83 c0 08 48 8d 49 08 41 83 f8 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Small_ARA_2147912986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Small.ARA!MTB"
        threat_id = "2147912986"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 8d 0c 30 41 ff c0 80 34 ?? ?? 44 3b c0 72 f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Small_ARA_2147912986_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Small.ARA!MTB"
        threat_id = "2147912986"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 4c 24 3b b2 62 30 4c 24 3c 32 d1 30 4c 24 3d 41 b0 3b 30 4c 24 3e 44 32 c1 30 4c 24 3f 41 b2 6d 30 4c 24 40 44 32 d1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

