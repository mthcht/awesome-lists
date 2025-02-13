rule TrojanDownloader_Win64_Hoogbot_A_2147814688_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Hoogbot.A"
        threat_id = "2147814688"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Hoogbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 68 6f 62 ?? ?? ?? ?? ?? 6f 74}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 61 76 61 2d 73 64 6b [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

