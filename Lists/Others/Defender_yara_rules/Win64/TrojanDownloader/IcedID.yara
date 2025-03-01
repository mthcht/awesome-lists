rule TrojanDownloader_Win64_IcedId_SIBA_2147787489_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/IcedId.SIBA!MTB"
        threat_id = "2147787489"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b c1 84 c0 75 ?? 4c 8b c9 41 ba ?? ?? ?? ?? 41 bb ?? ?? ?? ?? 41 0f b6 11 b8 ?? ?? ?? ?? 2b c2 8d 0c 80 41 8b c3 c1 e1 ?? f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 41 8b c3 83 c1 ?? f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 41 88 09 49 ff c1 49 83 ea ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

