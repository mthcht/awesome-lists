rule TrojanDownloader_Win64_Dlass_GVD_2147959404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Dlass.GVD!MTB"
        threat_id = "2147959404"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Dlass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 f4 4a 75 00 c8 b8 71 00 00 a2 0a 00 99 fa 45 ac e8 4b 71 00 00 d4 00 00 c5 c7 db 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

