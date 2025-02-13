rule TrojanDownloader_Win32_Vidar_A_2147895781_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vidar.A!MTB"
        threat_id = "2147895781"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 44 24 08 00 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 02 00 00 00 e8 ?? ?? 00 00 83 ec 0c 89 45 ?? c7 45 e0 ?? ?? ?? ?? 8b 45 ?? 89 04 24 e8 ?? ?? 00 00 83 ec 04 89 85 30 fe ff ff 66 c7 85 2c fe ff ff 02 00 c7 04 24 50 00 00 00 e8 ?? ?? 00 00 83 ec 04 66 89 85 2e fe ff ff c7 44 24 08 10 00 00 00 8d 85 2c fe ff ff 89 44 24 04 8b 45 ?? 89 04 24 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

