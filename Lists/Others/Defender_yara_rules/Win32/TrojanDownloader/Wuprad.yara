rule TrojanDownloader_Win32_Wuprad_A_2147629883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wuprad.A"
        threat_id = "2147629883"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wuprad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "affid=%s&action=down_load" ascii //weight: 1
        $x_1_2 = {10 27 00 00 7d 0a 6a 05 e8 ?? ?? ?? ?? 83 c4 04 6a 01}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 04 ff 24 95 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 83 c4 10 b8 01 00 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

