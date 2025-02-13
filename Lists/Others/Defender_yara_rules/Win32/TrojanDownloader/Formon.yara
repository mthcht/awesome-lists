rule TrojanDownloader_Win32_Formon_A_2147597365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Formon.A"
        threat_id = "2147597365"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Formon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 0c 85 f6 c7 45 fc 31 32 33 00 8d 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {2e 70 68 70 00 55 73 65 72 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_3 = "uid=%s&" ascii //weight: 1
        $x_1_4 = "AppInit_DLLs" ascii //weight: 1
        $x_1_5 = {25 64 2e 65 78 65 00 00 6c 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

