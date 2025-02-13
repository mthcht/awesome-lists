rule TrojanDownloader_Win32_Razy_MA_2147810505_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Razy.MA!MTB"
        threat_id = "2147810505"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 05 f4 1f 39 01 80 ff ff ff 0f 85 ?? ?? ?? ?? f7 05 f4 1f 39 01 ff ff ff ff 0f 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {33 35 d4 a3 57 00 33 35 d8 a3 57 00 33 35 dc a3 57 00 1b cf 33 35 e0 a3 57 00 33 35 e4 a3 57 00 33 35 e8 a3 57 00 c0 d6 fc 33 35 ec a3 57 00 f9 33 35 f0 a3 57 00 66 d3 c9 c0 de 97 33 35 f4 a3 57 00 80 fb 10 3b fc 33 35}  //weight: 1, accuracy: High
        $x_1_3 = "GetDiskFreeSpace" ascii //weight: 1
        $x_1_4 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_5 = "LockFile" ascii //weight: 1
        $x_1_6 = "UnmapViewOfFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

