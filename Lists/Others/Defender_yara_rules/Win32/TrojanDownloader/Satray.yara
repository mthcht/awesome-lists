rule TrojanDownloader_Win32_Satray_B_2147598878_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Satray.B"
        threat_id = "2147598878"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Satray"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "113"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\verclsid.exe" ascii //weight: 1
        $x_1_2 = "InProcServer32" ascii //weight: 1
        $x_1_3 = "CLSID\\{ACADABAF-1000-0010-8000-10AA006D2EA4}" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_5 = "EnableFirewall" ascii //weight: 1
        $x_1_6 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" ascii //weight: 1
        $x_1_7 = "\\drivers" ascii //weight: 1
        $x_1_8 = "http://o1a.cn/Counter/NewCounter.asp?Param=" ascii //weight: 1
        $x_1_9 = "My Beautiful girl!!!" ascii //weight: 1
        $x_1_10 = "d:\\MyDocument\\Visual Studio Projects\\Downloader  Project YU\\DownloaderMain\\DownloaderDll.pdb" ascii //weight: 1
        $x_1_11 = "ipconfig /all" ascii //weight: 1
        $x_1_12 = "http://o1a.cn/soso/mi/logo.gif" ascii //weight: 1
        $x_1_13 = "Physical Address. . . . . . . . . :" ascii //weight: 1
        $x_100_14 = {81 ec 0c 01 00 00 a1 a0 b0 00 10 53 56 57 89 84 24 14 01 00 00 8d 44 24 0c 50 68 3f 00 0f 00 6a 00 68 08 92 00 10 68 02 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 8b 1d ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 75 1b 8b 4c 24 0c 6a 00 6a 00 6a 01 6a 00 68 e0 91 00 10 51 ff d3}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

