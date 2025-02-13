rule TrojanDownloader_Win32_Bukvice_2147689832_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bukvice"
        threat_id = "2147689832"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bukvice"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 ec 00 02 00 00 68 ?? ?? ?? ?? 50 50 8d 44 24 0c 68 ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8d 44 24 14 83 c4 14 8d 50 01 8a 08 40 84 c9 75 f9 56 2b c2 6a 01 50 8d 4c 24 0c 51 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 14 6a 64 ff ?? ?? ?? ?? ?? 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 68 20 4f 41 00 6a 00 ff ?? ?? ?? ?? ?? 81 c4 00 02 00 00 c3}  //weight: 10, accuracy: Low
        $x_2_2 = "del /s /q \"killfile.bat\"" ascii //weight: 2
        $x_2_3 = "\\ServiceDownLoader.ini" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

