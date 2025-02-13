rule TrojanDownloader_Win32_Almanahe_A_2147609321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Almanahe.A"
        threat_id = "2147609321"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Almanahe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 ec fe ff ff 83 c0 01 89 85 ec fe ff ff 81 bd ec fe ff ff ?? ?? ?? ?? 7d 21 8b 8d ec fe ff ff 0f be 91 ?? ?? ?? ?? 81 f2 ff 00 00 00 8b 85 ec fe ff ff 88 90 ?? ?? ?? ?? eb c4}  //weight: 1, accuracy: Low
        $x_1_2 = {81 38 50 45 00 00 0f 85 d2 00 00 00 8b 4d dc 0f b7 51 14 8b 45 dc 8d 4c 10 18 89 8d d4 ef ff ff c7 45 fc 00 00 00 00 c7 85 d0 ef ff ff 00 00 00 00 eb 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

