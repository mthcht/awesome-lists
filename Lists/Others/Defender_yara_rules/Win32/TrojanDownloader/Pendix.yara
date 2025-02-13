rule TrojanDownloader_Win32_Pendix_C_2147602440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pendix.C"
        threat_id = "2147602440"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pendix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 7d c0 b9 10 00 00 00 b8 dd dd cc cc f3 ab 6a 00 6a 00 68 5c 10 40 00 68 1c 10 40 00 ?? ?? e8 41 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {68 5c 10 40 00 [0-5] 68 1c 10 40 00 [0-5] e8 41 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

