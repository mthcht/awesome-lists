rule TrojanDownloader_Win32_Anedl_A_2147651314_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Anedl.A"
        threat_id = "2147651314"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Anedl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/v \"load\" /t reg_sz /d" ascii //weight: 1
        $x_1_2 = {80 7d fb 01 75 ?? 81 fb b8 0b 00 00 76 ?? 6a 01 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 e8 03 00 00 e8 ?? ?? ?? ?? 6a 00 8d 45 ?? e8 ?? ?? ?? ?? ff 75 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

