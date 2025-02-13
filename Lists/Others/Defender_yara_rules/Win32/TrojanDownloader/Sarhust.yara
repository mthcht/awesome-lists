rule TrojanDownloader_Win32_Sarhust_A_2147643528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sarhust.A"
        threat_id = "2147643528"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sarhust"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" wide //weight: 1
        $x_1_2 = "wmiprvse.ini" wide //weight: 1
        $x_1_3 = "Don't find cmd.exe,please check again or upload the program!" ascii //weight: 1
        $x_1_4 = "NvSmartMaxUseDynamicDeviceGrids" ascii //weight: 1
        $x_1_5 = "RenInitInstance@12" ascii //weight: 1
        $x_1_6 = {83 c4 0c 8d 8d ?? ff ff ff e8 ?? ?? ?? ?? 8d 45 ?? 50 6a 00 8d 85 ?? ff ff ff 50 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 89 45 ?? 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_7 = {55 8b ec 81 ec ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? 00 00 83 c4 08 68 ?? ?? 00 00 ff 15 ?? ?? ?? ?? 8d 8d ?? ff ff ff e8 ?? ?? 00 00 8d 8d ?? ff ff ff e8 ?? ?? 00 00 8d 8d ?? ff ff ff e8 ?? ?? 00 00 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

