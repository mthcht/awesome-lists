rule TrojanDownloader_Win64_Tnega_RR_2147964029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Tnega.RR!MTB"
        threat_id = "2147964029"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 eb 03 d3 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 33 0f b6 c3 2a c1 04 36 41 30 00 ff c3 4d 8d 40 01 83 fb 19 7c d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

