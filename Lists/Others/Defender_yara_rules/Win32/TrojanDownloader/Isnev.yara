rule TrojanDownloader_Win32_Isnev_2147607942_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Isnev"
        threat_id = "2147607942"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Isnev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LookupPrivilegeValueA" ascii //weight: 1
        $x_1_2 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_3 = {57 69 6e 45 78 65 63 ?? ?? ?? 47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 41}  //weight: 1, accuracy: Low
        $x_1_4 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_5 = "WritePrivateProfileStringA" ascii //weight: 1
        $x_1_6 = {76 65 6e 73 69 6f 6e 00 6f 72 67 00 5c 73 79 73 74 65 6d 49 6e 66 6f 6d 61 74 69 6f 6e 73 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_7 = {5c 64 6f 77 6e 2e 74 78 74 00 00 00 74 78 74 00 69 6e 69 00 75 72 6c 6d 6f 6e 2e 64 6c 6c 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: High
        $x_1_8 = {62 69 61 6f 6a 69 00 00 6c 6f 63 61 6c 66 69 6c 65 00 00 00 63 6f 75 6e 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

