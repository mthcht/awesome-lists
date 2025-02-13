rule TrojanDownloader_Win64_ZeGost_CCHZ_2147905792_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/ZeGost.CCHZ!MTB"
        threat_id = "2147905792"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "ZeGost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 01 fe c8 88 01 48 ff c1 48 ff ca 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

