rule TrojanDownloader_Win64_Shelm_A_2147852181_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Shelm.A!MTB"
        threat_id = "2147852181"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 20 2b 45 fc 89 c1 48 8b 55 f0 48 8b 45 10 41 b9 00 00 00 00 41 89 c8 48 89 c1 48 8b 05 ?? ?? 00 00 ff d0 89 45 ec 8b 45 ec 48 98 48 01 45 f0 8b 45 ec 01 45 fc 83 7d ec ff 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Shelm_B_2147908193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Shelm.B!MTB"
        threat_id = "2147908193"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d 54 24 40 44 89 64 24 40 48 8b ce 44 89 64 24 44 ff 15 ?? 1f 00 00 85 c0 74 ?? 48 85 ff 75 ?? 8b 4c 24 40 83 c1 01 49 0f 42 cd ff 15 ?? 1f 00 00 eb ?? 8b 54 24 40 48 8b cf 03 d3 83 c2 01 49 0f 42 d5 ff 15 ?? 1f 00 00 48 85 c0 74 ?? 44 8b 44 24 40 4c 8d 4c 24 44 8b d3 48 8b ce 48 03 d0 48 8b f8 ff 15 ?? 1f 00 00 85 c0 74 ?? 03 5c 24 44 44 39 64 24 40}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

