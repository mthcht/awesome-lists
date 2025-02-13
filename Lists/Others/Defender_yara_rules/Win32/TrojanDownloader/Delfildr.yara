rule TrojanDownloader_Win32_Delfildr_A_2147683447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delfildr.A"
        threat_id = "2147683447"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfildr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d3 8d 45 ec 8b 4d fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ec 8b 45 08 8b 40 fc e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 a0 44 00 00 00 66 c7 45 d0 05 00 c7 45 cc 01 00 00 00 84 db 74 ?? 8d 45 e4 50 8d 45 a0 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 50 ff d7}  //weight: 1, accuracy: Low
        $x_1_3 = "setWeatherCity>" ascii //weight: 1
        $x_1_4 = "fuck360cnm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

