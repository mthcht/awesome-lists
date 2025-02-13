rule TrojanDownloader_Win32_QuasarRAT_B_2147906570_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QuasarRAT.B!MTB"
        threat_id = "2147906570"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 10 b9 00 10 00 00 8b 45 ?? 03 c1 89 45 ?? 03 d9 89 5d ?? 83 d6 ?? 89 75 ?? 2b f9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

