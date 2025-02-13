rule TrojanDownloader_Win32_Noitap_A_2147646047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Noitap.A"
        threat_id = "2147646047"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Noitap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 00 73 00 3f 00 2e 00 72 00 61 00 6e 00 64 00 3d 00 25 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "XXService.pdb" ascii //weight: 1
        $x_1_3 = {6a 3f 56 e8 ?? ?? ?? ?? 83 c4 1c bb ?? ?? ?? ?? 85 c0 74 05 bb ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 56 8d 54 24 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

