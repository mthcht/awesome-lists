rule TrojanDownloader_Win64_SalatStealer_CD_2147954066_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/SalatStealer.CD!MTB"
        threat_id = "2147954066"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d 8c 24 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 bc 24 ?? ?? ?? ?? 5a 72}  //weight: 2, accuracy: Low
        $x_2_2 = {48 2b c6 48 35 ?? ?? ?? ?? 0f b6 44 04 ?? 41 88 03 49 ff c3 4c 3b db 75}  //weight: 2, accuracy: Low
        $x_1_3 = "CelestialDownloader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

