rule TrojanDownloader_Win32_Malgentz_ATZ_2147921612_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Malgentz.ATZ!MTB"
        threat_id = "2147921612"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Malgentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 b4 8a 0a 88 4c 38 2e 8b 45 bc 8b 04 85 00 8f 01 10 80 4c 38 2d 04 8b 45 b8 40 89 46 04}  //weight: 1, accuracy: High
        $x_1_2 = {8b 75 b0 8b 45 bc 8b 0c 85 00 8f 01 10 8a 04 13 03 ce 88 44 19 2e 43 3b df}  //weight: 1, accuracy: High
        $x_1_3 = {89 75 fc 8b 45 0c 8b 00 8b 38 8b d7 c1 fa 06 8b c7 83 e0 3f 6b c8 38 8b 04 95 00 8f 01 10 f6 44 08 28 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

