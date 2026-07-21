rule TrojanDownloader_Win64_Cerbu_AH_2147974165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Cerbu.AH!MTB"
        threat_id = "2147974165"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {66 0f 6f e0 f3 0f 6f d0 66 0f da e5 66 0f 6f d8 66 0f 74 e0 66 0f fc de f3 0f 6f 02 0f 54 dc 66 0f 6f cc 0f 55 c8 0f 56 d9 0f 54 dc 0f 55 e2 0f 56 dc f3 0f 7f 1a 48 83 c2 10 48 8b c2 48 2b c7 49 3b c0 7c}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

