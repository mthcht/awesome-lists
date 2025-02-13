rule TrojanDownloader_Win64_Sliver_GA_2147931947_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Sliver.GA!MTB"
        threat_id = "2147931947"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 0f 57 ff 4c 8b 35 ca 5d 54 00 65 4d 8b 36 4d 8b 36 48 8b 44 24 08 48 83 c4 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

