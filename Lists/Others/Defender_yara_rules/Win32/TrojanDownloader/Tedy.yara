rule TrojanDownloader_Win32_Tedy_ARA_2147932416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tedy.ARA!MTB"
        threat_id = "2147932416"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b c8 0f b6 81 4d 2d 41 00 30 86 c5 58 41 00 83 c6 06 83 fe 12 0f 82 e9 fe ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

