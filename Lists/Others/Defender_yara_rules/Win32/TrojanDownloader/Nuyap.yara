rule TrojanDownloader_Win32_Nuyap_A_2147653910_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nuyap.A"
        threat_id = "2147653910"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuyap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 14 55 c6 44 24 15 52 c6 44 24 16 4c c6 44 24 17 44}  //weight: 1, accuracy: High
        $x_1_2 = {8a 1c 08 80 f3 90 88 1c 08 40 3b c2 7c f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

