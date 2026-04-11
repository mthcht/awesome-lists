rule TrojanDownloader_Win64_Midie_SX_2147966784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Midie.SX!MTB"
        threat_id = "2147966784"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {c7 44 24 04 00 04 00 00 8b 45 ec 89 04 24 a1 ?? ?? ?? ?? ff d0 8b 45 f0 89 44 24 04 8b 45 ec 89 04 24 e8 ?? ?? ?? ?? 8b 45 f0 89 04 24 e8}  //weight: 20, accuracy: Low
        $x_10_2 = {89 04 24 a1 ?? ?? ?? ?? ff d0 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 8b 45 f0 89 44 24 0c c7 44 24 08 ?? ?? ?? ?? c7 44 24 04 ?? ?? ?? ?? c7 04 24 00 00 00 00 a1}  //weight: 10, accuracy: Low
        $x_5_3 = "/create /sc ONLOGON /tn \"%s\" /tr \"%s\" /RL HIGHEST" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

