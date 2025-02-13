rule TrojanDownloader_Win32_Raren_B_2147652508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Raren.B"
        threat_id = "2147652508"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Raren"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 65 b1 53 c6 44 24 08 41 c6 44 24 09 64 c6 44 24 0a 76}  //weight: 1, accuracy: High
        $x_1_2 = "{abc-_-cba}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

