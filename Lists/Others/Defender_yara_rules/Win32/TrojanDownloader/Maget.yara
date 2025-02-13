rule TrojanDownloader_Win32_Maget_DEA_2147761689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Maget.DEA!MTB"
        threat_id = "2147761689"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Maget"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 c2 0f b6 c0 89 44 24 10 8a 44 04 14 88 44 1c 14 8b 44 24 10 88 4c 04 14 8a 44 1c 14 02 c2 0f b6 c0 8a 44 04 14 32 04 3e 88 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

