rule TrojanDownloader_Win64_Xmrig_ARAX_2147956836_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Xmrig.ARAX!MTB"
        threat_id = "2147956836"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 44 24 50 48 03 c2 0f b6 0c 07 30 4c 15 90 48 ff c2 30 08 48 3b d3 72 e6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

