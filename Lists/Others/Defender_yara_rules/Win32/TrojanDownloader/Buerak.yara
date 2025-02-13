rule TrojanDownloader_Win32_Buerak_G_2147759202_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Buerak.G!MTB"
        threat_id = "2147759202"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Buerak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f3 03 f1 34 1e [0-64] c1 c6 0b [0-64] 83 c2 0d 33 15}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 59 06 34 1e [0-32] 8d 49 04 [0-64] 8b c3 [0-48] 8b cf 83 e9 89 33 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {32 c1 e9 0b [0-48] 89 3d [0-48] c7 05 [0-64] 0f b6 42 ?? 8b c3 [0-48] c7 45 [0-48] 03 4c 24 [0-48] 0f b6 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

