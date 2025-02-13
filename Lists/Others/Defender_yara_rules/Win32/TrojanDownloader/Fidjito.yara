rule TrojanDownloader_Win32_Fidjito_A_2147649833_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fidjito.A"
        threat_id = "2147649833"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fidjito"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6a 4f 57 ff d6 57 ff 15 ?? ?? ?? ?? 69 c0 60 ea 00 00 53 6a 50 57 89 45 f4 ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 2c 33 c0 80 b0 ?? ?? ?? ?? ?? 40 83 f8 0f 7c f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

