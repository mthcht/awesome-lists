rule TrojanDownloader_Win64_Fragtor_ARA_2147924888_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Fragtor.ARA!MTB"
        threat_id = "2147924888"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 0c 30 ff c0 88 0c 3b ff c3 3b 44 24 40 72 ef}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

