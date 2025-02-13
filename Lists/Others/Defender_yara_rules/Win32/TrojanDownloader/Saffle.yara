rule TrojanDownloader_Win32_Saffle_A_2147630130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Saffle.A"
        threat_id = "2147630130"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Saffle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 d0 07 00 00 ff 15 ?? ?? ?? ?? ff 15 [0-32] 3d e8 03 00 00 7c 26 3d d0 07 00 00 7d 1f}  //weight: 1, accuracy: Low
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "%s\\hosts.txt" ascii //weight: 1
        $x_3_4 = {2b c2 3d e8 03 00 00 7c 26 3d d0 07 00 00 7d 1f 6a ff 6a 00 6a 00 ff 15 ?? ?? 40 00 85 c0 75 0f}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

