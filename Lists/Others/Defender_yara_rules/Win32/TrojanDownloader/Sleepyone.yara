rule TrojanDownloader_Win32_Sleepyone_A_2147583204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sleepyone.A"
        threat_id = "2147583204"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sleepyone"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2200"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {40 45 43 48 4f 20 4f 46 46 0d 0a 3e 20 74 65 6d 70 2e 72 65 67 20 45 43 48 4f 20 52 45 47 45 44 49 54 34 0d 0a 3e 3e 20 74 65 6d 70 2e 72 65 67 20 45 43 48 4f 2e 0d 0a 3e 3e 20 74 65 6d 70 2e 72 65 67 20 45 43 48 4f 20 5b 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5d 0d 0a 3e 3e 20 74 65 6d 70 2e 72 65 67 20 45 43 48 4f 20 22 53 68 65 6c 6c 22 3d 22 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 1000, accuracy: High
        $x_1000_2 = {6a 00 6a 00 6a 00 8d 45 e4 b9 ?? ?? 41 00 8b 15 ?? ?? 41 00 e8 ?? ?? ff ff 8b 45 e4 e8 ?? ?? ff ff 50 68 ?? ?? 41 00 6a 00 e8}  //weight: 1000, accuracy: Low
        $x_1000_3 = "add hklm\\software\\microsoft\\windows\\currentversion\\run /v services /d" ascii //weight: 1000
        $x_1000_4 = {8d 45 c4 ba 03 00 00 00 e8 ?? ?? ff ff 8b 45 c4 e8 ?? ?? ff ff 50 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 e8}  //weight: 1000, accuracy: Low
        $x_100_5 = {77 69 6e 64 6f 77 73 ?? 73 65 72 76 69 63 65 73 2e 65 78 65}  //weight: 100, accuracy: Low
        $x_100_6 = {77 69 6e 64 6f 77 73 ?? 75 73 65 72 69 6e 69 74 2e 65 78 65}  //weight: 100, accuracy: Low
        $x_100_7 = "START /WAIT REGEDIT /S temp.reg" ascii //weight: 100
        $x_100_8 = ":\\windows\\services.exe /f" ascii //weight: 100
        $x_100_9 = "DEL temp.reg" ascii //weight: 100
        $x_100_10 = {72 65 67 00 6f 70 65 6e 00}  //weight: 100, accuracy: High
        $x_100_11 = "c:\\x.exe" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*) and 2 of ($x_100_*))) or
            ((3 of ($x_1000_*))) or
            (all of ($x*))
        )
}

