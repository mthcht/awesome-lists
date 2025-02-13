rule TrojanDownloader_Win32_Bunabom_A_2147682682_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bunabom.A"
        threat_id = "2147682682"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunabom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\SOFTWARE\\PlayOnlineUS\\" ascii //weight: 1
        $x_1_2 = {2f 74 68 67 72 2e 61 73 70 3f 6d 61 63 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 6e 64 20 4f 4b 21 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 ff 30 64 89 20 c6 45 fb 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

