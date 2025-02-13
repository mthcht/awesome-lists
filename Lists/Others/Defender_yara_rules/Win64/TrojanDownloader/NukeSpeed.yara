rule TrojanDownloader_Win64_NukeSpeed_F_2147926527_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/NukeSpeed.F!MTB"
        threat_id = "2147926527"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "NukeSpeed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f9 41 0f b6 cf 0f b6 8c 88 10 b1 04 00 33 f9 33 fb 44 8b c7 41 89 7d 3c 45 33 c1 45 8b c8 45 89 45 40 45 33 ca 41 8b d9 45 89 4d 44 41 33 db 41 89 5d 48 8b cb 48 c1 e9 18 44 0f b6 9c 88 10 b1 04 00 8b cb c1 e9 08 0f b6 d1 8b 8c 90 10 b1 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {c1 ea 16 69 ca 80 96 98 00 ba 10 00 00 00 2b f9 81 ff 40 42 0f 00 8d 8f 40 42 0f 00 0f 43 cf 89 48 38 8d 4a 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

