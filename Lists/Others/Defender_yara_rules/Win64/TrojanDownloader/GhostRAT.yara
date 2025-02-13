rule TrojanDownloader_Win64_GhostRAT_PAY_2147929193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/GhostRAT.PAY!MTB"
        threat_id = "2147929193"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 8d 15 d9 82 24 00 48 8d 4c 24 38 e8 37 f0 ff ff 90 48 8d 15 bf 70 1b 00 48 8d 4c 24 60 e8 25 f0 ff ff 90 4c 8d 44 24 38 48 8d 54 24 60 48 8d 8c 24 90 00 00 00 e8 7d ed ff ff 90 48 8d 4c 24 60 e8 72 f0 ff ff 90 48 8d 4c 24 38 e8 67 f0 ff ff 48 8d 8c 24 90 00 00 00 e8 4a eb ff ff 4c 8d 05 5b 70 1b 00 48 8d 15 54 82 24 00 48 8d 0d 6d 82 24 00 e8 d0 fc ff ff 48 8d 15 41 82 24 00 48 8d 0d aa 70 1b 00 e8 dd fd ff ff c7 44 24 28 05 00 00 00 48 c7 44 24 20 00 00 00 00 4c 8d 0d 1c 70 1b 00 4c 8d 05 96 70 1b 00 48 8d 15 b7 70 1b 00 33 c9 ff 15 77 5a 1b 00}  //weight: 4, accuracy: High
        $x_1_2 = "C:\\Users\\Public\\kingsoft.dat" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Public\\macfee.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

