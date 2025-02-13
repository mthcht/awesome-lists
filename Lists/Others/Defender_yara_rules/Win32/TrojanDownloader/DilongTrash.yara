rule TrojanDownloader_Win32_DilongTrash_2147810346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/DilongTrash!dha"
        threat_id = "2147810346"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "DilongTrash"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 73 14 00 00 0a 0a 02 7b 01 00 00 04 17 06 17 1b 6f ?? ?? ?? ?? d2 9c 02 7b 01 00 00 04 1b 06 17 1f 09 6f ?? ?? ?? ?? d2 9c 02 7b 01 00 00 04 1f 7b 06 17 1f 09 6f ?? ?? ?? ?? d2 9c 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

